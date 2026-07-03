import os
import re
import yaml
import argparse
import subprocess
import traceback
import sys
import clang.cindex
from jinja2 import FileSystemLoader, Environment
from dotenv import load_dotenv

try:
    load_dotenv()
except ImportError:
    pass

# paths matching the local environment, overridable via environment variables or env file
DEFAULT_VCVARS_PATH = os.environ.get("VCVARS64_PATH", "")
DEFAULT_DETOURS_INC = os.environ.get("DETOURS_INC", "")
DEFAULT_DETOURS_LIB = os.environ.get("DETOURS_LIB", "")
DEFAULT_FRIDA_INC = os.environ.get("FRIDA_INC", "")
DEFAULT_FRIDA_LIB = os.environ.get("FRIDA_LIB", "")
DEFAULT_ENGINES_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engines.yaml")

# Regex Constants
_HEX_PATTERN = re.compile(r"^0x[0-9a-f]+$", flags=re.I)
_LIB_PATTERN = re.compile(r"^[a-z0-9_\-\.]+\.lib$", flags=re.I)
_CALLING_CONV_PATTERN = re.compile(r"\b(__stdcall|__cdecl|__fastcall|WINAPI|APIENTRY|CALLBACK|CDECL|STDMETHODCALLTYPE|STDAPICALLTYPE)\b", flags=re.I)
_SIGNATURES_BLOCK_PATTERN = re.compile(r"//\s*@signatures-start(.*?)(?://\s*@signatures-end)", flags=re.S | re.I)
_HOOK_TAG_PATTERN = re.compile(r"//\s*@(?!signatures\b)(\w+)-start", flags=re.I)


# C++ Preamble for clang to understand Windows macros
CPP_PREAMBLE = """
#define WINAPI __stdcall
#define CALLBACK __stdcall
#define APIENTRY __stdcall
#define CDECL __cdecl
#define STDMETHODCALLTYPE __stdcall
#define STDAPICALLTYPE __stdcall
"""

ENGINES = {}

def load_engines(config_path=DEFAULT_ENGINES_CONFIG):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Engine registry configuration file not found at: '{config_path}'")
        
    print(f"[*] Loading engine registry from: {config_path}")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse engine configuration file '{config_path}': {e}")
        
    if not isinstance(data, dict):
        raise ValueError(f"Engine configuration from '{config_path}' must be a dictionary.")
        
    # required fields per paradigm
    PARADIGM_SCHEMAS = {
        "inline_hook": ["template", "cast_format", "libs_arg", "inc_arg"],
        "default":     ["template", "libs_arg", "inc_arg"]
    }
        
    loaded_engines = {}
    for paradigm, engines_data in data.items():
        if not isinstance(engines_data, dict):
            raise ValueError(f"Paradigm definitions in configuration must be dictionaries. Section '{paradigm}' is not.")
        
        p_lower = paradigm.lower()
        loaded_engines[p_lower] = {}
        
        required_fields = PARADIGM_SCHEMAS.get(p_lower, PARADIGM_SCHEMAS["default"])
        
        for engine_name, engine_data in engines_data.items():
            if not isinstance(engine_data, dict):
                raise ValueError(f"Engine definitions under paradigm '{paradigm}' must be dictionaries. Section '{engine_name}' is not.")
                
            missing = [f for f in required_fields if f not in engine_data]
            if missing:
                raise ValueError(f"Engine '{engine_name}' under paradigm '{paradigm}' configuration is missing required fields: {missing}")
                

            extra_libs = engine_data.setdefault("extra_libs", [])
            if not isinstance(extra_libs, list) or not all(isinstance(l, str) for l in extra_libs):
                raise ValueError(f"Engine '{engine_name}' under paradigm '{paradigm}' 'extra_libs' must be a list of strings.")
                
            for lib in extra_libs:
                if not _LIB_PATTERN.match(lib):
                    raise ValueError(f"Engine '{engine_name}' extra_libs item '{lib}' is invalid. Must only contain alphanumeric characters, dash, underscore, dot, and end with '.lib'.")
    
            loaded_engines[p_lower][engine_name.lower()] = engine_data
        
    if not loaded_engines:
        raise ValueError(f"Engine registry configuration file '{config_path}' defined no paradigms/engines.")
        
    return loaded_engines

def get_engine_config(engine_name, paradigm=None):
    engine_lower = engine_name.lower()
    if paradigm:
        paradigm_lower = paradigm.lower()
        if paradigm_lower in ENGINES and engine_lower in ENGINES[paradigm_lower]:
            cfg = ENGINES[paradigm_lower][engine_lower].copy()
            cfg["paradigm"] = paradigm_lower
            return cfg
        return None
        
    for p, engines in ENGINES.items():
        if engine_lower in engines:
            cfg = engines[engine_lower].copy()
            cfg["paradigm"] = p
            return cfg
            
    return None


def analyze_type(clang_type, name):
    depth = 0
    curr = clang_type
    while curr.kind == clang.cindex.TypeKind.POINTER:
        depth += 1
        curr = curr.get_pointee()
    
    underlying_spelling = curr.spelling
    
    is_char_ptr = False
    if depth == 1:
        canonical_spelling = curr.get_canonical().spelling
        if canonical_spelling in ("char", "const char"):
            is_char_ptr = True
            
    expr = name
    for _ in range(depth):
        expr = f"ReadPointer({expr})"
        
    return {
        "pointer_depth": depth,
        "underlying_type": underlying_spelling,
        "is_char_ptr": is_char_ptr,
        "safe_read_expr": expr
    }


def parse_signatures_file(combined_content, tu):

    m = _SIGNATURES_BLOCK_PATTERN.search(combined_content)
    if not m:
        raise ValueError("Could not find the signatures block in logic file. Ensure you use '// @signatures-start' and '// @signatures-end' markers.")

    start_line = combined_content.count('\n', 0, m.start()) + 1
    end_line = start_line + combined_content.count('\n', m.start(), m.end())

    signatures = {}
    for node in tu.cursor.get_children():
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            loc = node.location
            if loc.file and loc.file.name == 'logic_file.cpp':
                if start_line <= loc.line <= end_line:
                    calling_convention = ""
                    tokens = list(node.get_tokens())
                    for t in tokens:
                        if t.spelling == node.spelling or t.spelling == '(':
                            break
                        m_cc = _CALLING_CONV_PATTERN.search(t.spelling)
                        if m_cc:
                            calling_convention = m_cc.group(1)

                    params = []
                    for arg in node.get_arguments():
                        type_info = analyze_type(arg.type, arg.spelling)
                        params.append({
                            "type": arg.type.spelling,
                            "name": arg.spelling,
                            "pointer_depth": type_info["pointer_depth"],
                            "underlying_type": type_info["underlying_type"],
                            "is_char_ptr": type_info["is_char_ptr"],
                            "safe_read_expr": type_info["safe_read_expr"]
                        })

                    signatures[node.spelling] = {
                        "function_name": node.spelling,
                        "return_type": node.result_type.spelling,
                        "calling_convention": calling_convention,
                        "parameters": params
                    }
    return signatures

def parse_hook_implementations(combined_content, tu):
    
    matches = list(_HOOK_TAG_PATTERN.finditer(combined_content))
    if not matches:
        return {}

    expected_hooks = {m.group(1) for m in matches}
    
    hooks_map = {}
    
    for node in tu.cursor.get_children():
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            loc = node.location
            if loc.file and loc.file.name == 'logic_file.cpp':
                if node.spelling in expected_hooks:
                    params = []
                    for arg in node.get_arguments():
                        type_info = analyze_type(arg.type, arg.spelling)
                        params.append({
                            "type": arg.type.spelling,
                            "name": arg.spelling,
                            "pointer_depth": type_info["pointer_depth"],
                            "underlying_type": type_info["underlying_type"],
                            "is_char_ptr": type_info["is_char_ptr"],
                            "safe_read_expr": type_info["safe_read_expr"]
                        })
                    hooks_map[node.spelling] = params
    #check if we found all of them
    missing = expected_hooks - set(hooks_map.keys())
    if missing:
        raise ValueError(f"Hook implementation functions {missing} were not found or failed to parse.")

    return hooks_map

def extract_engines_from_config(config):
    engines_val = config.get("engines", ["detours"])
    if isinstance(engines_val, str):
        engines = [engines_val.lower()]
    elif isinstance(engines_val, list):
        if not all(isinstance(e, str) for e in engines_val):
            raise ValueError("'engines' list must contain only strings.")
        engines = [e.lower() for e in engines_val]
    else:
        raise ValueError("'engines' must be a string or a list of strings.")

    if not engines:
        raise ValueError("'engines' cannot be empty.")
    return engines

def normalize_policy(data):
    if not isinstance(data, dict):
        raise ValueError("Policy data must be a dictionary.")
    
    if "configure" not in data:
        raise ValueError("Missing 'configure' section in policy YAML.")
    config = data["configure"]
    if not isinstance(config, dict):
        raise ValueError("'configure' section must be a YAML object.")
    engines = extract_engines_from_config(config)
    config["engines_list"] = engines

    if "hooks" not in data or not isinstance(data["hooks"], list):
        raise ValueError("Missing 'hooks' list in policy YAML.")

    for idx, hook in enumerate(data["hooks"]):
        if not isinstance(hook, dict):
            raise ValueError(f"Hook at index {idx} must be a YAML object.")

        hook.setdefault("module", "")
        
        addr_res = hook.setdefault("address_resolution", {"strategy": "export"})
        if isinstance(addr_res, dict) and "strategy" in addr_res:
            strategy = addr_res["strategy"].lower()
            if strategy == "offset" and "rva_offset" in addr_res:
                rva_offset = addr_res["rva_offset"]
                if isinstance(rva_offset, int):
                    rva_offset = hex(rva_offset)
                if isinstance(rva_offset, str):
                    addr_res["rva_offset"] = "0x" + rva_offset[2:].upper()

        behaviors = hook.setdefault("behaviors", {})
        
        perf_metrics = behaviors.setdefault("performance_metrics", {})
        perf_metrics.setdefault("execution_time", False)

        run_monitoring = behaviors.setdefault("runtime_monitoring", {})
        run_monitoring.setdefault("log_arguments", [])

        sec_policy = behaviors.setdefault("security_policy", {})
        sec_policy.setdefault("pre_hook", None)
        sec_policy.setdefault("post_hook", None)
        sec_policy.setdefault("pre_hook_params", [])
        sec_policy.setdefault("post_hook_params", [])

def handle_logic_file(data, policy_dir):
    config = data["configure"]

    if "logic_file" not in config:
        raise ValueError("Missing mandatory 'logic_file' in configure block.")
    
    if not isinstance(config["logic_file"], str):
        raise ValueError("'logic_file' must be a string path.")
    
    abs_logic_path = os.path.normpath(os.path.join(policy_dir, config["logic_file"]))
    if not os.path.isfile(abs_logic_path):
        raise ValueError(f"'logic_file' path does not exist or is not a file: {abs_logic_path}")

    # Replacing windows path for including it in the C++ code (for #include directive)
    config["logic_file_abs"] = abs_logic_path.replace("\\", "/")

    try:
        with open(abs_logic_path, "r", encoding="utf-8") as lf:
            logic_content = lf.read()

        combined_content = CPP_PREAMBLE + "\n" + logic_content
        index = clang.cindex.Index.create()
        tu = index.parse('logic_file.cpp', args=['-std=c++17'], unsaved_files=[('logic_file.cpp', combined_content)])

        signatures_map = parse_signatures_file(combined_content, tu)
        hooks_map = parse_hook_implementations(combined_content, tu)
    except Exception as e:
        raise ValueError(f"Failed to parse blocks from logic_file at {abs_logic_path}: {e}")

    for idx, hook in enumerate(data["hooks"]):
        func_name = hook.get("function_name")
        if not func_name or not isinstance(func_name, str):
            continue
        if func_name in signatures_map:
            sig_data = signatures_map[func_name]
            hook["parameters"] = sig_data["parameters"]
            hook["return_type"] = sig_data["return_type"]
            hook["calling_convention"] = sig_data["calling_convention"]
        else:
            raise ValueError(f"Hook prototype for '{func_name}' not found in logic_file.")

        behaviors = hook["behaviors"]
        sec_policy = behaviors["security_policy"]

        pre_hook_name = sec_policy["pre_hook"]
        if pre_hook_name is not None:
            if not isinstance(pre_hook_name, str):
                raise ValueError(f"Hook '{func_name}' security_policy 'pre_hook' must be a string.")
            if pre_hook_name not in hooks_map:
                raise ValueError(f"Pre-hook function '{pre_hook_name}' not found in logic_file.")
            sec_policy["pre_hook_params"] = hooks_map[pre_hook_name]

        post_hook_name = sec_policy["post_hook"]
        if post_hook_name is not None:
            if not isinstance(post_hook_name, str):
                raise ValueError(f"Hook '{func_name}' security_policy 'post_hook' must be a string.")
            if post_hook_name not in hooks_map:
                raise ValueError(f"Post-hook function '{post_hook_name}' implementation block (with // @{post_hook_name}-start tag) not found in logic_file.")
            sec_policy["post_hook_params"] = hooks_map[post_hook_name]

def validate_policy(data):
    config = data["configure"]
    engines = config["engines_list"]
    user_paradigm = config.get("paradigm")
    if user_paradigm:
        user_paradigm = user_paradigm.lower()

    engine_paradigms = set()
    for engine in engines:
        cfg = get_engine_config(engine, paradigm=user_paradigm)
        if not cfg:
            if user_paradigm:
                raise ValueError(f"Unsupported hooking engine '{engine}' for paradigm '{user_paradigm}'.")
            else:
                raise ValueError(f"Unsupported hooking engine: '{engine}'.")
        engine_paradigms.add(cfg["paradigm"])

    if len(engine_paradigms) > 1:
        raise ValueError("All specified engines must belong to the same paradigm.")
    
    engine_paradigm = list(engine_paradigms)[0]

    if user_paradigm and user_paradigm != engine_paradigm:
        raise ValueError(
            f"Paradigm mismatch! Engines {engines} belong to paradigm '{engine_paradigm}', "
            f"but you specified '{user_paradigm}' in configure."
        )

    if "process" not in config:
        raise ValueError("Missing mandatory 'process' setting in configure block.")
    target_process = config["process"]
    if not isinstance(target_process, str):
        raise ValueError("'process' must be a string.")

    for idx, hook in enumerate(data["hooks"]):
        if "function_name" not in hook:
            raise ValueError(f"Hook at index {idx} must specify a 'function_name'.")
        func_name = hook["function_name"]
        if not isinstance(func_name, str):
            raise ValueError(f"Hook at index {idx} must specify a 'function_name' string.")

        module = hook["module"]
        if not isinstance(module, str):
            raise ValueError(f"Hook '{func_name}' 'module' must be a string.")

        addr_res = hook["address_resolution"]
        if not isinstance(addr_res, dict):
            raise ValueError(f"Hook '{func_name}' 'address_resolution' must be a YAML object.")

        if "strategy" not in addr_res:
            raise ValueError(f"Hook '{func_name}' is missing address resolution 'strategy'.")

        strategy = addr_res["strategy"].lower()
        if strategy not in ["export", "offset"]:
            raise ValueError(
                f"Unsupported address resolution strategy '{strategy}' in hook '{func_name}'. "
                f"Supported: 'export', 'offset'."
            )

        if strategy == "offset":
            if "rva_offset" not in addr_res:
                raise ValueError(f"Hook '{func_name}' uses strategy 'offset' but is missing 'rva_offset'.")
            rva_offset = addr_res["rva_offset"]
            if not isinstance(rva_offset, str) or not _HEX_PATTERN.match(rva_offset):
                raise ValueError(f"Hook '{func_name}' uses strategy 'offset' but 'rva_offset' is not a valid hex string.")

        behaviors = hook["behaviors"]
        perf_metrics = behaviors["performance_metrics"]
        if not isinstance(perf_metrics.get("execution_time"), bool):
            raise ValueError(f"Hook '{func_name}' performance metric 'execution_time' must be a boolean.")

        run_monitoring = behaviors["runtime_monitoring"]
        log_args = run_monitoring["log_arguments"]
        if not isinstance(log_args, list):
            raise ValueError(f"Hook '{func_name}' log_arguments must be a list of strings.")

        # Determine valid identifiers that can be logged
        valid_log_targets = [p["name"] for p in hook.get("parameters", [])]
        if hook.get("return_type", "").lower() != "void":
            valid_log_targets.append("result")

        for arg in log_args:
            if not isinstance(arg, str):
                raise ValueError(f"Hook '{func_name}' log_argument must be a string.")
            if arg not in valid_log_targets:
                raise ValueError(f"Hook '{func_name}' log_argument '{arg}' is not a valid parameter name or 'result'.")

        sec_policy = behaviors["security_policy"]
        pre_hook_name = sec_policy["pre_hook"]
        post_hook_name = sec_policy["post_hook"]
        pre_hook_params = sec_policy["pre_hook_params"]
        post_hook_params = sec_policy["post_hook_params"]

        # Check pre_hook_params matches target function parameters
        target_param_names = [p["name"] for p in hook.get("parameters", [])]
        for p in pre_hook_params:
            p_name = p["name"]
            if p_name not in target_param_names:
                raise ValueError(
                    f"Pre-hook '{pre_hook_name}' for hook '{func_name}' references parameter '{p_name}' "
                    f"which does not exist in the target function's parameters: {target_param_names}"
                )

        # Validate that post_hook_params matches target function parameters or is 'result'
        for p in post_hook_params:
            p_name = p["name"]
            is_valid = (p_name in target_param_names) or (p_name == "result" and hook.get("return_type", "").lower() != "void")
            if not is_valid:
                raise ValueError(
                    f"Post-hook '{post_hook_name}' for hook '{func_name}' references parameter '{p_name}' "
                    f"which does not exist in the target function's parameters "
                )

def validate_and_parse_policy(policy_path):
    print(f"Parsing policy: {policy_path}")
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            content = f.read()
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {e}")
    except Exception as e:
        raise ValueError(f"Failed to read policy file: {e}")

    normalize_policy(data)

    policy_dir = os.path.dirname(os.path.abspath(policy_path))
    handle_logic_file(data, policy_dir)

    validate_policy(data)

    return data

def handle_address_resolution(hook, engine, engine_cfg):

    addr_res = hook["address_resolution"]
    strategy = addr_res["strategy"].lower()
    module = hook["module"]
    func_name = hook["function_name"]

    if module:
        module_expr = 'hMod'
    else:
        module_expr = 'GetModuleHandleA(NULL)'

    cast_prefix = engine_cfg["cast_format"].format(name=func_name)

    if strategy == "export":
        return f'{cast_prefix}GetProcAddress({module_expr}, "{func_name}")'
    elif strategy == "offset":
        rva = addr_res["rva_offset"]
        return f'{cast_prefix}((char*){module_expr} + {rva})'
    
    raise ValueError(f"Invalid strategy: {strategy}")

def generate_cpp_code(policy_data, engine, output_cpp_path):
    
    engine_cfg = get_engine_config(engine)
    if not engine_cfg:
        raise ValueError(f"Engine config not found for '{engine}'")

    for hook in policy_data["hooks"]:
        hook["address_resolution_cpp"] = handle_address_resolution(hook, engine, engine_cfg)

    templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), trim_blocks=True, lstrip_blocks=True)

    template_file = engine_cfg["template"]
    template = env.get_template(template_file)

    # Compute relative path to the logic file from output C++ directory
    abs_output_dir = os.path.dirname(os.path.abspath(output_cpp_path))
    logic_file_abs = policy_data["configure"]["logic_file_abs"]
    try:
        logic_file_rel = os.path.relpath(logic_file_abs, abs_output_dir).replace("\\", "/")
    except ValueError:
        logic_file_rel = logic_file_abs

    rendered_code = template.render(
        hooks=policy_data["hooks"],
        engine=engine,
        logic_file_rel=logic_file_rel
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_cpp_path)), exist_ok=True)
    with open(output_cpp_path, "w", encoding="utf-8") as f:
        f.write(rendered_code)

    print(f"[+] Rendered C++ written to: {output_cpp_path}")

def validate_safe_path(path, name, is_dir=False, must_exist=True):
    if not isinstance(path, str):
        raise ValueError(f"{name} must be a string path. Check your .env file or command-line arguments.")
    
    if must_exist:
        if not os.path.exists(path):
            raise FileNotFoundError(f"{name} path does not exist on disk: {path}")
        if is_dir and not os.path.isdir(path):
            raise ValueError(f"{name} path is not a directory: {path}")
        if not is_dir and not os.path.isfile(path):
            raise ValueError(f"{name} path is not a file: {path}")

def compile_dll(args, engine, cpp_source, dll_dest):
    engine_cfg = get_engine_config(engine)
    if not engine_cfg:
        raise ValueError(f"Engine config not found for '{engine}' during compilation")
    inc_path = getattr(args, engine_cfg["inc_arg"])
    lib_path = getattr(args, engine_cfg["libs_arg"])
    vcvars_path = args.vcvars

    validate_safe_path(inc_path, f"Engine '{engine}' include directory ({engine_cfg['inc_arg']})", is_dir=True, must_exist=True)
    validate_safe_path(lib_path, f"Engine '{engine}' library file ({engine_cfg['libs_arg']})", is_dir=False, must_exist=True)
    validate_safe_path(cpp_source, "C++ source file path", is_dir=False, must_exist=True)
    validate_safe_path(dll_dest, "Output DLL path", is_dir=False, must_exist=False)
    validate_safe_path(vcvars_path, "vcvars64.bat path", is_dir=False, must_exist=True)

    compile_cmd = f'call {subprocess.list2cmdline([vcvars_path])} && '

    rt_flag = args.rt_link

    cl_args = [
        "cl.exe",
        "/LD",        
        rt_flag,      
        "/EHsc",      
        "/O2",        
        "/std:c++17", 
        f'/Fo{os.path.splitext(dll_dest)[0]}.obj',
        cpp_source,
    ]

    cl_args.append(f'/I{inc_path}')
    cl_args.append(lib_path)
    for lib in engine_cfg["extra_libs"]:
        cl_args.append(lib)

    cl_args.append("/link")
    cl_args.append(f"/OUT:{dll_dest}")

    final_cmd = compile_cmd + subprocess.list2cmdline(cl_args)
    print(f"Executing compile command for engine '{engine}':\n    {final_cmd}\n")

    proc = subprocess.run(
        final_cmd,
        shell=True,
        capture_output=True,
        text=True
    )

    if proc.returncode != 0:
        print(f"MSVC COMPILATION FAILED FOR ENGINE: {engine}")
        print(proc.stdout)
        print(proc.stderr)
        return False
    else:
        print(f"MSVC COMPILATION SUCCESSFUL FOR ENGINE: {engine}!")
        print(f"Target payload DLL generated: {dll_dest}")
        base_name = os.path.splitext(dll_dest)[0]
        for ext in [".obj", ".lib", ".exp"]:
            temp_file = base_name + ext
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
        return True

def get_output_paths(engine, output_cpp, output_dll, use_suffix=False):
    if use_suffix:
        cpp_base, cpp_ext = os.path.splitext(output_cpp)
        dll_base, dll_ext = os.path.splitext(output_dll)
        return f"{cpp_base}_{engine}{cpp_ext}", f"{dll_base}_{engine}{dll_ext}"
    else:
        return output_cpp, output_dll

def main():
    parser = argparse.ArgumentParser(description="Policy DSL Source-to-Source Transpiler")
    parser.add_argument("policy", nargs="?", default="scada_policy.yaml", help="Path to the policy DSL file")
    parser.add_argument("--output-cpp", default="generated_hook.cpp", help="Destination path of generated C++ code")
    parser.add_argument("--output-dll", default="generated_hook.dll", help="Destination path of compiled Windows DLL")
    parser.add_argument("--vcvars", default=DEFAULT_VCVARS_PATH, help="Absolute path to MSVC's vcvars64.bat script")
    parser.add_argument("--detours-include", default=DEFAULT_DETOURS_INC, help="Microsoft Detours include directory")
    parser.add_argument("--detours-lib", default=DEFAULT_DETOURS_LIB, help="Microsoft Detours static library (.lib) file path")
    parser.add_argument("--frida-include", default=DEFAULT_FRIDA_INC, help="Frida-Gum include directory")
    parser.add_argument("--frida-lib", default=DEFAULT_FRIDA_LIB, help="Frida-Gum static library (.lib) file path")
    parser.add_argument("--rt-link", default="/MT", choices=["/MT", "/MD"], help="Runtime library link model: /MT (static) or /MD (dynamic)")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--gen-only", action="store_true", help="Only render C++ template code without compiling")
    mode_group.add_argument("--compile-only", action="store_true", help="Only compile the existing output-cpp file")
    mode_group.add_argument("--validate-only", action="store_true", help="Only validate the policy YAML without generating or compiling code")
    parser.add_argument("--engines-config", default=DEFAULT_ENGINES_CONFIG, help="Path to engines registry YAML configuration file")
    args = parser.parse_args()

    global ENGINES
    try:
        ENGINES = load_engines(args.engines_config)
    except Exception as e:
        print(f"Error loading engines: {e}")
        return 1

    if not args.compile_only and not os.path.exists(args.policy):
        print(f"Error: Policy DSL configuration file '{args.policy}' not found.")
        return 1

    try:
        policy_data = {}
        engines = ["detours"]

        if not args.compile_only:
            policy_data = validate_and_parse_policy(args.policy)
            engines = policy_data["configure"]["engines_list"]
            
            if args.validate_only:
                print("[+] Policy validation successful.")
                return 0
            
            use_suffix = len(engines) > 1
            for engine in engines:
                current_cpp, current_dll = get_output_paths(engine, args.output_cpp, args.output_dll, use_suffix)
                generate_cpp_code(policy_data, engine, current_cpp)
        else:
            # Load policy anyway to find engines
            if os.path.exists(args.policy):
                try:
                    with open(args.policy, "r", encoding="utf-8") as f:
                        policy_data = yaml.safe_load(f) or {}
                except Exception:
                    pass
            
            config = policy_data.get("configure") or {}
            engines = extract_engines_from_config(config)

        if args.gen_only:
            print("Generation completed. Skipping compile stage (--gen-only).")
            return 0

        overall_success = True
        use_suffix = len(engines) > 1
        for engine in engines:
            current_cpp, current_dll = get_output_paths(engine, args.output_cpp, args.output_dll, use_suffix)
            if not os.path.exists(current_cpp):
                print(f"Error: Source C++ file '{current_cpp}' not found for compilation.")
                overall_success = False
                continue
            
            success = compile_dll(args, engine, current_cpp, current_dll)
            if not success:
                overall_success = False

        return 0 if overall_success else 1

    except (ValueError, FileNotFoundError) as e:
        print(f"Configuration Error: {e}")
        return 1
    except Exception as e:
        print(f"Error during transpilation process: {e}")
        traceback.print_exc()
        return 1


sys.exit(main())

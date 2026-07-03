# HookDesigner

HookDesigner is a tool developed as part of a Master's thesis. It provides a declarative, YAML-based Domain-Specific Language (DSL) for specifying function hooking policies, which are then automatically transpiled into production-ready Windows C++ DLL source code targeting one or more hooking engines (e.g. Microsoft Detours, Frida-Gum). The generated DLLs are compiled via MSVC and injected into target processes using a DLL injector, enabling runtime interception, monitoring, and mutation of function calls in Windows binaries.

---

## Table of Contents

1. [Project Structure](#project-structure)
   - [Pipeline Stages](#pipeline-stages)
2. [Components](#components)
   - [Transpiler (`transpiler.py`)](#transpiler-transpilerpy)
   - [Injector (`injector.cpp`)](#injector-injectorcpp)
   - [SCADA Engine Simulator (`scada_engine.cpp`)](#scada-engine-simulator-scada_enginecpp)
   - [Template System](#template-system)
3. [Policy YAML Schema](#policy-yaml-schema)
4. [Template Architecture](#template-architecture)
5. [Hooking Engine Abstraction](#hooking-engine-abstraction)
6. [Build & Usage Guide](#build--usage-guide)
7. [Limitations & Future Work](#limitations--future-work)
8. [Dependencies](#dependencies)

---

## Project Structure

```
HookDesigner/
├── transpiler.py              # Core transpiler: parse → extract → render → compile
├── injector.cpp               # C++ DLL injector (inject/eject/launch modes)
├── scada_engine.cpp           # SCADA simulator target with exported hookable functions
├── engines.yaml               # Engine registry: maps engine names to templates, libs, args
├── requirements.txt           # Python dependencies
├── .env.example               # Template for local environment paths (MSVC, Detours, Frida)
│
├── templates/                 # Jinja2 C++ template files
│   ├── detours_template.cpp   # Detours engine template (includes sub-templates)
│   ├── frida_template.cpp     # Frida-Gum engine template
│   ├── _hook_body.cpp         # Shared hook body: arg capture, pre/post logic, telemetry
│   ├── _dllmain.cpp           # Shared DLL entry point (DllMain)
│   └── _user_logic_helpers.cpp# Shared helpers
│
└── test_run/                  # Test artifacts and example policies
    ├── policy_full.yaml       # Example multi-hook, multi-engine policy
    ├── policy_logic.cpp       # Example user logic file with signatures and callbacks
    ├── hook_full_detours.cpp  # Generated Detours output (for reference)
    └── hook_full_frida.cpp    # Generated Frida output (for reference)
```

---

### Pipeline Stages

| Stage | Component | Responsibility |
|-------|-----------|----------------|
| **1. Input** | Policy YAML + User Logic C++ | Declarative hook specification and custom callback implementations |
| **2. Parse & Validate** | `transpiler.py` (YAML + libclang) | Parse policy, normalize defaults, extract C++ signatures from the logic file, validate cross-references |
| **3. Generate** | Jinja2 templates | Render engine-specific C++ DLL source with all hook bodies, telemetry, SEH wrappers |
| **4. Compile** | MSVC (`cl.exe` via `vcvars64.bat`) | Compile the generated C++ into a Windows DLL linked against the selected engine's libraries |
| **5. Inject** | `injector.exe` | Load the DLL into the target process and invoke `InitializeHooks` remotely |
| **6. Execute** | Hook DLL inside target | Intercept function calls, execute pre/post logic, log telemetry, call originals via trampoline |
| **7. Eject** | `injector.exe` | Unload the DLL and safely detach all hooks remotely via `DeinitializeHooks`, restoring the target process's original execution |

> [!NOTE]
> The first four stages (Input, Parse & Validate, Generate, Compile) are meant to be conducted "offline" on a local development workstation. The resulting compiled DLL can then be transferred to the target system to perform the remaining three stages (Inject, Execute, Eject), which do not require a Python environment or LLVM/libclang to be installed.

---

## Components

### Transpiler (`transpiler.py`)

**Purpose**: The transpiler is the central orchestrator. It reads a YAML policy file, extracts C++ function signatures from the user's logic file using `libclang`, renders engine-specific C++ source code via Jinja2 templates, and optionally compiles the result into a DLL using MSVC.

#### Execution Modes

The transpiler supports three mutually exclusive operational modes:

| Mode | CLI Flag | Behavior |
|------|----------|----------|
| **Full pipeline** | *(default)* | Parse → Validate → Generate C++ → Compile DLL |
| **Generate only** | `--gen-only` | Parse → Validate → Generate C++ (skip compilation) |
| **Compile only** | `--compile-only` | Compile an existing generated C++ file (skip parsing/generation) |
| **Validate only** | `--validate-only` | Parse → Validate YAML Policy (skip generation and compilation) |

#### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `policy` | `scada_policy.yaml` | Path to the policy YAML file |
| `--output-cpp` | `generated_hook.cpp` | Destination path for the generated C++ source |
| `--output-dll` | `generated_hook.dll` | Destination path for the compiled DLL |
| `--vcvars` | `$VCVARS64_PATH` | Path to MSVC's `vcvars64.bat` |
| `--detours-include` | `$DETOURS_INC` | Detours header include directory |
| `--detours-lib` | `$DETOURS_LIB` | Detours static library (`.lib`) path |
| `--frida-include` | `$FRIDA_INC` | Frida-Gum header include directory |
| `--frida-lib` | `$FRIDA_LIB` | Frida-Gum static library (`.lib`) path |
| `--rt-link` | `/MT` | MSVC runtime linking model (`/MT` static or `/MD` dynamic) |
| `--gen-only` | `false` | Only render C++ without compiling |
| `--compile-only` | `false` | Only compile existing C++ without parsing/generating |
| `--validate-only` | `false` | Only validate the policy YAML |
| `--engines-config` | `engines.yaml` | Path to the engine registry configuration file |


#### Features

1. **libclang for signature extraction**: Rather than using fragile regex-based C++ parsing, the transpiler creates an in-memory translation unit via `libclang` with a Windows-macro preamble (defining `WINAPI`, `CALLBACK`, etc.) and parses the AST. This correctly handles complex types, pointer nesting, and calling conventions.

2. **Tag-based convention for user logic**: The user's logic file uses comment-based markers (`// @signatures-start`, `// @FunctionName-start`) to delineate regions. This avoids requiring a custom parser or build system — the file is simultaneously a valid C++ header (included via `#include` in the generated code) and a structured input to the transpiler.

3. **Separation of policy from logic**: The YAML policy specifies *what* to hook and *which behaviors* to apply, while the C++ logic file specifies *how* (the actual callback implementations). This separation allow user to write C++ code in a usual code editor with syntax highlighting/intellisense enabled. It also enables the same logic file to be reused across different policies and engines.

---

### Injector (`injector.cpp`)

**Purpose**: A standalone C++ executable for injecting compiled hook DLLs into target Windows processes. It supports three operational modes and handles the full lifecycle of DLL injection, hook initialization, and clean ejection.

#### Operational Modes

| Mode | Syntax | Description |
|------|--------|-------------|
| **inject** | `injector.exe inject <PID> <DLL_PATH>` | Inject DLL into a running process and call `InitializeHooks` |
| **eject** | `injector.exe eject <PID> <DLL_PATH>` | Call `DeinitializeHooks` and unload DLL from a running process |
| **launch** | `injector.exe launch <EXE_PATH> <DLL_PATH> [args...]` | Launch process in suspended state, inject DLL, call `InitializeHooks`, then resume |

The default mode (when no mode keyword is provided) is `inject`:
```
injector.exe <PID> <DLL_PATH>
```
#### Design Decisions

1. **Separate `InitializeHooks` and `DeinitializeHooks` call**: Rather than attaching/detaching hooks in `DllMain` (which runs under the OS loader lock and has severe restrictions on what APIs can be called), the injector explicitly calls the exported `InitializeHooks` function via a second remote thread after injection completes. This avoids loader-lock deadlocks. Similarly, `DeinitializeHooks` is called before unloading the DLL to ensure a clean exit.

2. **Launch mode with `CREATE_SUSPENDED`**: The launch mode creates the target process in a suspended state, injects the DLL and installs hooks *before* the process's main thread runs. This guarantees hooks are active from the very first function call, which is critical for intercepting initialization-time behavior.

---

### SCADA Engine Simulator (`scada_engine.cpp`)

**Purpose**: A dummy AI generated test target that simulates a very simple SCADA process with multiple exported functions of varying signatures. It serves as a realistic, reproducible hooking target for integration testing.

#### Exported Functions

All functions use `extern "C"` linkage and are marked `__declspec(dllexport)` and `__declspec(noinline)` to ensure they are exported by name and are not optimized away by the compiler.

#### Architecture

The simulator runs a multi-threaded engine loop:

- **3 worker threads** each call all exported functions in a cycle with an 800ms interval.
- Parameters are varied per cycle (e.g., alternating `complexityWeight` between 600.0 and 250.0) to trigger different code paths in the hook callbacks.
- On startup, the simulator prints its **PID**, **base address**, and **RVA offsets** for all key functions, enabling the test pipeline to dynamically populate the policy with correct offsets.
- The engine runs until the user presses Enter, then gracefully shuts down all worker threads.

---

### Template System

The Jinja2 template system is the code generation core. It takes the validated, enriched policy data and produces complete, compilable C++ source files. See [Template Architecture](#template-architecture) for full details.

---

## Policy YAML Schema

The policy YAML file is the primary input to the transpiler. It consists of two top-level sections: `configure` and `hooks`.

### `configure` Section

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `paradigm` | `string` | No | *(inferred from engine)* | Hooking paradigm (e.g., `inline_hook`). If specified, validates that all engines belong to this paradigm. |
| `engines` | `string \| list[string]` | No | `["detours"]` | One or more hooking engines to generate code for. Each engine produces a separate output file. |
| `process` | `string` | **Yes** | — | Name of the target process executable (e.g., `scada_engine.exe`). |
| `logic_file` | `string` | **Yes** | — | Relative path (from the policy file) to the C++ user logic file containing signatures and callbacks. |

### `hooks` Section

A list of hook definitions. Each hook specifies a target function and its associated behaviors.

#### Hook Object

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `function_name` | `string` | **Yes** | — | Name of the target function to hook (must match a signature in the logic file). |
| `module` | `string` | No | `""` | Name of the DLL/EXE module containing the target function. If empty, uses the main process module. |
| `address_resolution` | `object` | No | `{strategy: "export"}` | How to resolve the function's address at runtime. See below. |
| `behaviors` | `object` | No | `{}` | Behavioral policies to apply to this hook. See below. |

#### `address_resolution` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `strategy` | `string` | **Yes** | Resolution strategy: `"export"` (via `GetProcAddress`) or `"offset"` (via base address + RVA). |
| `rva_offset` | `string` | **If `strategy: offset`** | Hexadecimal RVA offset (e.g., `"0x1A30"`). Integers are also accepted and auto-converted to hex. |

#### `behaviors` Object

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `performance_metrics` | `object` | `{}` | Performance measurement configuration. |
| `runtime_monitoring` | `object` | `{}` | Argument and return value logging configuration. |
| `security_policy` | `object` | `{}` | Pre-hook and post-hook callback configuration. |

##### `performance_metrics`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `execution_time` | `bool` | `false` | If `true`, measure hook latency using `QueryPerformanceCounter` and include it in log output. |

##### `runtime_monitoring`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_arguments` | `list[string]` | `[]` | List of parameter names (and/or `"result"`) to capture and log. Values are captured both before and after the original function call; if a value was mutated, both the original and mutated values are logged with an arrow notation (`value -> new_value`). |

##### `security_policy`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pre_hook` | `string \| null` | `null` | Name of the pre-hook callback function (called *before* the original function). Must be tagged with `// @<name>-start` in the logic file. |
| `post_hook` | `string \| null` | `null` | Name of the post-hook callback function (called *after* the original function). Must be tagged with `// @<name>-start` in the logic file. |

Pre-hook and post-hook callback parameters are automatically extracted from the logic file via `libclang`. The transpiler validates that each callback parameter name matches a parameter of the target function (post-hooks may additionally reference `result`).

### Complete Example

```yaml
configure:
  paradigm: inline_hook
  engines:
    - detours
    - frida
  process: scada_engine.exe
  logic_file: "policy_logic.cpp"

hooks:
  - module: scada_engine.exe
    function_name: ParseProprietaryPacket
    address_resolution:
      strategy: offset
      rva_offset: "0x1A30"
    behaviors:
      performance_metrics:
        execution_time: true
      runtime_monitoring:
        log_arguments:
          - packetBuffer
          - complexityWeight
          - result
      security_policy:
        pre_hook: SharedPacketPreHook

  - module: scada_engine.exe
    function_name: LogTaskResult
    address_resolution:
      strategy: export
    behaviors:
      runtime_monitoring:
        log_arguments:
          - taskId
          - status
      security_policy:
        pre_hook: GenericEnterLog
        post_hook: LogTaskResult_post
```

---

## Template Architecture

The template system uses Jinja2's `{% include %}` mechanism to compose engine-specific templates from shared partial templates, allowing each engine to define its own hook installation/removal logic.

### Template Files

#### `detours_template.cpp`

The Detours template. Generates a complete DLL source file that:

- Includes Windows headers and `<detours.h>`.
- Defines the `HookGuard` RAII struct for tracking in-flight hook executions.
- Includes `_user_logic_helpers.cpp` (which itself `#include`s the user's logic file).
- For each hook: generates a `typedef` for the original function pointer type, a static `True<FunctionName>` pointer, and a `Hooked<FunctionName>` function that includes `_hook_body.cpp`.
- Implements `EnlistAllThreads()` to enumerate process threads for Detours' thread-update mechanism.
- Exports `InitializeHooks()`: resolves target addresses, begins a Detours transaction, attaches all hooks, commits.
- Exports `DeinitializeHooks()`: begins a transaction, detaches all hooks, commits, spin-waits for in-flight executions.
- Includes `_dllmain.cpp`.

#### `frida_template.cpp`

The top-level Frida-Gum template. Structurally parallel to the Detours template, but uses Frida APIs:

- Includes `"frida-gum.h"`.
- Omits `HookGuard` (Frida handles it automatically).
- Uses `gum_interceptor_replace()` / `gum_interceptor_revert()` equivalent to `DetourAttach` / `DetourDetach`.
- `InitializeHooks()` calls `gum_init_embedded()` and obtains a `GumInterceptor`.
- `DeinitializeHooks()` calls `gum_interceptor_flush()` to drain in-flight calls, then `gum_deinit_embedded()`.

#### `_hook_body.cpp` (Shared Partial)

Generates the body of each `Hooked<FunctionName>` function. This is included once per hook within a `{% for hook in hooks %}` loop. It generates:

1. **Argument capture on entry**: For each logged argument, captures the value before the original call
2. **Performance timing start**: If `execution_time` is enabled, queries `QueryPerformanceCounter`.
3. **Pre-hook invocation**: If a `pre_hook` is defined, calls `RunPreLogic_<name>(...)`.
4. **Original function call**: Calls `True<FunctionName>(...)` via the trampoline pointer, capturing the return value in `__hook_result`.
5. **Post-hook invocation**: If a `post_hook` is defined, calls `RunPostLogic_<name>(...)`, passing parameters and/or `__hook_result`.
6. **Performance timing end**: Computes elapsed milliseconds, if specified.
7. **Argument capture on exit**: Re-captures logged arguments to detect mutations.
8. **Telemetry output**: Builds a log line with thread ID, argument values (showing `original -> mutated` for changed values), and latency.
9. **Return**: Returns `__hook_result` (or void).

#### `_user_logic_helpers.cpp` (Shared Partial)

Provides utility functions and SEH-protected wrappers included at the top of every generated file:

- `#include "{{ logic_file_rel }}"` — includes the user's logic file.
- `CopyStringImpl` / `CopyString` — SEH-protected string copy to safely read potentially invalid `char*` pointers.
- `ReadPointerImpl` / `ReadPointer` — SEH-protected templated pointer dereference. Returns a fallback value if the pointer is null or points to invalid memory.
- `LogSEHException` — logs SEH exception details without using C++ objects (to comply with MSVC's restriction on mixing `__try`/`__except` with C++ destructors).
- `RunPreLogic_<name>` / `RunPostLogic_<name>` — Generated for each unique pre/post hook. Wraps the user's callback in a `__try`/`__except` block to catch access violations or other exceptions during user logic execution, preventing crashes in the target process.

The template uses Jinja2 sets (`{% set generated_pre_hooks = [] %}`) to track already-generated wrappers and avoid duplicate definitions when the same hook callback is shared across multiple target functions.

#### `_dllmain.cpp` (Shared Partial)

A minimal `DllMain` entry point that:

- For Detours: checks `DetourIsHelperProcess()` and returns early.
- On `DLL_PROCESS_ATTACH`: calls `DisableThreadLibraryCalls` to suppress `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` notifications.
- Does not attach/detach hooks in `DllMain` (deferred to `InitializeHooks` / `DeinitializeHooks`).

### Template Variables

All templates receive the following Jinja2 context variables:

| Variable | Type | Description |
|----------|------|-------------|
| `hooks` | `list[dict]` | Fully enriched list of hook objects with all normalized fields, extracted parameters, generated `address_resolution_cpp` expressions |
| `engine` | `string` | Current engine name (e.g., `"detours"`, `"frida"`) |
| `logic_file_rel` | `string` | Relative path from the output C++ file to the user's logic file (for `#include`) |

Each `hook` object within `hooks` contains the fields from the YAML schema plus transpiler-enriched fields:

| Field | Description |
|----------------|-------------|
| `parameters` | List of parameter dicts with `type`, `name`, `pointer_depth`, `underlying_type`, `is_char_ptr`, `safe_read_expr` |
| `return_type` | C++ return type string |
| `calling_convention` | Detected calling convention if specified (e.g., `"__stdcall"`, `""`) |
| `address_resolution_cpp` | Generated C++ expression for resolving the function address |

---

## Hooking Engine Abstraction

### `engines.yaml` Registry

The engine registry is a YAML file that maps paradigm names to engine definitions. The registry can be easily extended with new paradigms/engines.

```yaml
inline_hook:
  detours:
    template: "detours_template.cpp"
    cast_format: "(True{name}_t)"
    libs_arg: "detours_lib"
    inc_arg: "detours_include"
    extra_libs:
      - "User32.lib"
      - "Advapi32.lib"

  frida:
    template: "frida_template.cpp"
    cast_format: "(gpointer)"
    libs_arg: "frida_lib"
    inc_arg: "frida_include"
    extra_libs:
      - "User32.lib"
      - "Advapi32.lib"
      - "Ole32.lib"
      - "Shell32.lib"
```

#### Registry Fields

| Field | Required | Description |
|-------|----------|-------------|
| `template` | Yes | Jinja2 template filename (in `templates/` directory) |
| `cast_format` | Yes (for `inline_hook`) | Python format string for casting `GetProcAddress` results. `{name}` is replaced with the function name. |
| `libs_arg` | Yes | Name of the CLI argument providing the engine's static library path (maps to `argparse` attribute) |
| `inc_arg` | Yes | Name of the CLI argument providing the engine's include directory (maps to `argparse` attribute) |
| `extra_libs` | No (default `[]`) | Additional Windows `.lib` files to link (validated against `^[a-z0-9_\-\.]+\.lib$`) |


## Build & Usage Guide

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| **Python** | ≥ 3.8 | Transpiler runtime |
| **MSVC** (Visual Studio Build Tools) | 2022+ | C++ compiler (`cl.exe`) |
| **Microsoft Detours** | Latest | Inline hooking library (if using Detours engine) |
| **Frida-Gum** (devkit) | Latest | Inline hooking library (if using Frida engine) |
| **LLVM/Clang** | ≥ 18.0 | `libclang` shared library for signature extraction |

### Environment Setup

1. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment paths**: Copy `.env.example` to `.env` and fill in your local paths:
   ```ini
   # MSVC Configuration
   VCVARS64_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat

   # Microsoft Detours Configuration
   DETOURS_INC=C:\Detours\Detours-main\include
   DETOURS_LIB=C:\Detours\Detours-main\lib.X64\detours.lib

   # Frida-Gum Configuration
   FRIDA_INC=C:\Path\To\Frida
   FRIDA_LIB=C:\Path\To\Frida\frida-gum.lib
   ```

3. **Compile the SCADA simulator** (for testing):
   ```bash
   build_engine.bat
   ```

4. **Compile the injector** (using a Developer Command Prompt for VS):
   ```bash
   cl.exe /EHsc /O2 injector.cpp /I"C:\Detours\include" "C:\Detours\lib.X64\detours.lib"
   ```

### Writing a Policy YAML

Create a YAML file that declares the target process, the logic file, the hooking engine(s), and the list of functions to hook with their behaviors. For a detailed reference see the [Policy YAML Schema](#policy-yaml-schema) section.

### Writing the User Logic C++ File

The logic file contains two types of content:

1. **Signature declarations** enclosed in `// @signatures-start` and `// @signatures-end` markers:

```cpp
// @signatures-start
int UpdateSensor(int id, double val);
// @signatures-end
```

2. **Hook callback implementations** each preceded by a `// @<FunctionName>-start` tag:

```cpp
// @ClampSensorValue-start
void ClampSensorValue(double& val) {
    if (val > 100.0) {
        val = 100.0;  // Clamp to safe range
    }
}
```

Parameters of pre/post hook callbacks must be passed by reference if we want the callback to mutate permanently the target function's arguments (pre-hook) or return value (post-hook).

> [!IMPORTANT]
> **Shared Callbacks and Parameter Naming**
> 
> If you reuse a pre/post-hook callback across multiple different target functions to modify arguments, the callback's parameter names and types must exactly match those of the target functions. 
> 
> Because you declare the target function signatures in your logic file, you can safely **rename their parameters** (while preserving the original types and order) to unify them and match your shared callback's expected parameter names.

**Example:**
If `TargetA(possible other args, int param1)` and `TargetB(int differentName, possible other args)` both need the same pre-hook to modify their integer argument, unify their parameter names to `val` in your logic file:

```cpp
// @signatures-start
int TargetA(..., int val); // 'param1' renamed to 'val'
int TargetB(int val, ...); // 'differentName' renamed to 'val'
// @signatures-end

// @SharedModifier-start
void SharedModifier(int& val) {
    val = 42; // This callback now applies to both functions
}
```

### Running the Transpiler

**Full pipeline** (generate + compile):
```bash
python transpiler.py policy.yaml --output-cpp hook.cpp --output-dll hook.dll
```

**Generate C++ only** (no compilation):
```bash
python transpiler.py policy.yaml --output-cpp hook.cpp --gen-only
```

**Validate policy only**:
```bash
python transpiler.py policy.yaml --validate-only
```

**Multi-engine generation** (produces `hook_detours.cpp`, `hook_detours.dll`, `hook_frida.cpp`, `hook_frida.dll`):
```bash
python transpiler.py policy.yaml --output-cpp hook.cpp --output-dll hook.dll
```
When the policy specifies multiple engines, output files are automatically suffixed with the engine name.

### Injecting the DLL

**Into a running process**:
```bash
injector.exe inject <PID> hook.dll
```

**Launch a new process with injection**:
```bash
injector.exe launch scada_engine.exe hook.dll
```

**Eject a previously injected DLL**:
```bash
injector.exe eject <PID> hook.dll
```

---

## Limitations & Future Work

- **Logging Mechanism**: The telemetry and logging mechanism currently present in the generated hooks is temporary and logs directly to the console. In future iterations, this will be extended to serialize and send intercepted data asynchronously to a centralized database for persistent storage and analysis.

---

## Dependencies

### Python Dependencies (`requirements.txt`)

| Package | Version | Purpose |
|---------|---------|---------|
| `jinja2` | ≥ 3.0.0 | Template engine for C++ code generation |
| `pyyaml` | ≥ 6.0 | YAML parser for policy files and engine registry |
| `python-dotenv` | ≥ 1.0.0 | `.env` file loading for environment path configuration |
| `clang` | ≥ 18.0.0 | Python bindings for `libclang` AST traversal |
| `libclang` | ≥ 18.0.0 | LLVM/Clang shared library for C++ signature extraction |

### C++ Dependencies

| Library | Purpose | Required For |
|---------|---------|-------------|
| **Microsoft Detours** | Inline function hooking (transactional API) | Detours engine |
| **Frida-Gum** (C devkit) | Inline function hooking (`GumInterceptor` API) | Frida engine |
| **Windows SDK** | Win32 APIs (`VirtualAllocEx`, `CreateRemoteThread`, `Toolhelp32`, etc.) | All components |
| **MSVC C++ Runtime** | Standard library, SEH support | All components |

### Build Tools

| Tool | Purpose |
|------|---------|
| **MSVC `cl.exe`** | C++ compiler for DLL generation |
| **`vcvars64.bat`** | Sets up the MSVC 64-bit build environment |

---

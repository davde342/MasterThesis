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
   - [Telemetry & Metrics Performance Guidelines](#telemetry--metrics-performance-guidelines)
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

4. **Sensible Defaults with an Escape Hatch (Telemetry Expressions & Pointer Dereferencing)**:
   - **Sensible Defaults**: In telemetry conditions and log format strings, referencing standalone parameter variables (e.g., `input_paramName`) automatically generates type-safe memory reads using `ReadPointer(...)` or `(uintptr_t)(...)` based on type analysis. Policy authors do not need to write `ReadPointer` or dereference primitives manually for standalone parameters.
   - **Escape Hatch & Member Access**: Policy authors can write arbitrary C++ expressions, custom local variables (declared in `pre_hook` / `post_hook`), address-of operators, or explicit C++ casts. 
   
   > [!IMPORTANT]
   > **Member Access Requires Manual Safety:** When accessing struct or class fields through pointers (e.g., `input_pStruct->field`), the transpiler detects member access (`->` or `.`) and **bypasses automatic pointer dereferencing**. In this case, automatic crash protection is not applied, so **the policy author must explicitly handle memory safety manually** (e.g., by wrapping the member path in `ReadPointer(...)` as in `ReadPointer(input_pStruct->field)` or verifying non-null pointers).




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
| `log_rules` | `list[object]` | `[]` | Logging rules configuration. |
| `security_policy` | `object` | `{}` | Pre-hook and post-hook callback configuration. |

##### `performance_metrics`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `execution_time` | `bool` | `false` | If `true`, measure hook latency using `QueryPerformanceCounter`. |
| `counters` | `list[object]` | `[]` | List of Prometheus counter metric definitions. |
| `gauges` | `list[object]` | `[]` | List of Prometheus gauge metric definitions. |
| `histograms` | `list[object]` | `[]` | List of Prometheus histogram metric definitions. |

###### Metric Objects (`counters`, `gauges`, `histograms`)

Each metric item defined inside `counters`, `gauges`, or `histograms` supports the following schema:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | `string` | **Yes** | — | Unique metric name identifier within the hook. |
| `description` | `string` | No | `""` | Help string / description for the Prometheus metric family. |
| `condition` | `string` | No | `"true"` | Boolean C++ telemetry expression evaluated to determine if the metric is updated. |
| `value` | `string` | **Gauges & Histograms** | — | C++ telemetry expression to observe or set (e.g., `latency`, `input_<param>`, `output_<param>`, `__hook_result`, or global variable). |
| `buckets` | `list[float]` | No (**Histograms**) | `[0.001, 0.005, ...]` | Upper bounds for histogram buckets. Default is `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0]`. Must be a non-empty, strictly increasing list of positive numbers. |
| `label` | `dict[string, string]` | No | `{}` | Key-value dictionary specifying dynamic Prometheus label mapping (e.g. `{ label_key: "expression" }`). At most 1 dynamic label per metric is allowed. |

###### Metric Configuration Example

```yaml
performance_metrics:
  execution_time: true
  counters:
    - name: "cs_enter_total"
      description: "Total EnterCriticalSection calls"
    - name: "wait_single_failed_total"
      description: "Wait failures"
      condition: "__hook_result == WAIT_FAILED"
  gauges:
    - name: "cs_active_depth"
      description: "Current active threads holding critical sections"
      value: "g_cs_active_depth.load()"
  histograms:
    - name: "cs_enter_wait_time"
      description: "Distribution of critical section acquisition wait times"
      value: "latency"
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
```

##### `log_rules`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | `"rule_N"` | Name identifier for the log rule (auto-generated as `rule_1`, `rule_2`, etc. if omitted). |
| `condition` | `string` | `"true"` | Boolean C++ telemetry expression evaluated to determine if log fires. |
| `level` | `string` | `"info"` | Log level (`trace`, `debug`, `info`, `warn`, `error`, `critical`). |
| `arguments` | `list[string]` | `[]` | List of parameter names (`input_<param>` or `output_<param>`) or `__hook_result` to capture for auto-generated format strings. |
| `format` | `string` | `null` | Custom format string supporting placeholders (`{tid}`, `{__hook_result}`, `{input_<param>}`, `{output_<param>}`). |

###### Ways to Specify `log_rules`

1. **Empty / Default Rule (`- {}`)**
   Uses full defaults (`name: rule_1`, `level: info`, `condition: true`, auto-generated format string):
   ```yaml
   log_rules:
     - {}
   ```
   *Generated Log Message:* `"[HOOK FunctionName] [rule_1] called"`

2. **Auto-Generated Format String with Arguments**
   Specifies variables to log while letting the transpiler construct the format string automatically:
   ```yaml
   log_rules:
     - name: "log_args"
       level: "info"
       arguments:
         - input_lpSubKey
         - input_dwOptions
   ```
   *Generated Log Message:* `"[HOOK FunctionName] [log_args] | input_lpSubKey={input_lpSubKey} | input_dwOptions={input_dwOptions}"`

3. **Custom Format String with Placeholders**
   Defines an explicit log message format using placeholders like `{tid}`, `{__hook_result}`, `{input_<param>}`, or `{output_<param>}` (with optional C++ format specifiers like `:x`):
   ```yaml
   log_rules:
     - name: "reg_open_failed"
       condition: "__hook_result != 0"
       level: "warn"
       format: "[WARN] RegOpenKeyExA FAILED | key=\"{input_lpSubKey}\" access=0x{input_samDesired:x} error={__hook_result}"
   ```

4. **Multiple Conditional Rules**
   Attach multiple log rules with distinct conditions, levels, and formatters to a single hook:
   ```yaml
   log_rules:
     - name: "on_success"
       condition: "__hook_result == 0"
       level: "debug"
       arguments:
         - input_lpSubKey
     - name: "on_failure"
       condition: "__hook_result != 0"
       level: "error"
       format: "[ERROR] Failed to open key '{input_lpSubKey}' with code {__hook_result}"
   ```

5. **No Logging (Omitted or Empty List)**
   Omit `log_rules` entirely or set it to `[]`:
   ```yaml
   behaviors:
     log_rules: []
   ```
   *Behavior:* No log rules will be transpiled for this hook.

###### Validation Constraints for `log_rules`

The transpiler validates all `log_rules` in `process_log_rules` and will raise a `ValueError` if any of the following constraints are violated:

- **Dictionary Structure**: Each item in `log_rules` must be a YAML object (`dict`).
- **Unique Rule Names**: Rule names must be unique within the same hook. Auto-generated names (`rule_1`, `rule_2`) respect this constraint.
- **Allowed Log Levels**: `level` must be one of: `trace`, `debug`, `info`, `warn`, `error`, or `critical`.
- **Mutual Exclusion (`arguments` vs `format`)**: A rule **cannot** specify both `arguments` and `format`. Use `arguments` for auto-generated format strings, or `format` for custom log formatting.
- **Argument List Rules**:
  - `arguments` must be a list of strings.
  - Arguments within a single rule must be unique (no duplicate parameter names).
  - Every argument name must start with `input_` or `output_` matching a valid function parameter (e.g. `input_lpSubKey`), or be `__hook_result`.
- **Format String Placeholders**: Placeholders inside `format` strings can reference:
  - `{tid}` (Thread ID)
  - `{latency}` (Execution time in milliseconds)
  - `{__hook_result}` (Return value of the hooked function)
  - `{input_<param>}` or `{output_<param>}` (Target function parameters)
  - Custom C++ expressions, struct fields (e.g. `{input_pStruct->field}`), or local variables declared in `pre_hook` / `post_hook` callbacks.
  - Placeholders support C++ format specifiers following a colon (e.g., `{input_samDesired:x}`).
- **Telemetry Requirement**: If `log_rules` are present on any hook, top-level `configure.telemetry` must be configured (e.g., `logger: spdlog`).

#### Telemetry & Metrics Performance Guidelines

When designing metrics (Counters, Gauges, Histograms) for high-frequency or hot-path hooked functions (e.g., `EnterCriticalSection`, `ReadFile`, `WaitForSingleObject`), adhere to the following best practices:

1. **Validation & Low-Cardinality Metric Labels**:
   - Avoid using high-cardinality dynamic variables (such as thread IDs `{tid}`, pointer addresses `{input_buf_ptr}`, or timestamps) inside Prometheus metric label expressions.
   - Prometheus best practices explicitly state: *“Labels should only be used for low-cardinality dimensions (e.g. HTTP status codes, error types, method names).”* High-cardinality values belong in **logs**, not metric labels.

2. **Thread-Local / Direct Metric Caching**:
   - For hooks with dynamic low-cardinality labels, HookDesigner automatically utilizes a `thread_local static` metric cache (`ThreadLocalMetricCache` / `ThreadLocalHistogramCache`).
   - The first invocation for a given label set fetches the metric reference from `prometheus::Family::Add()`, while subsequent calls on the same thread bypass Prometheus's internal `std::mutex` lock, achieving near zero-cost updates on the hot path.

3. **Promote Label-less Counters for Hot Paths**:
   - For extremely high-frequency functions, prefer label-less counters. Label-less metrics use direct global references (`g_PromMetric_->Increment()`) which perform lock-free atomic updates (`std::atomic<double>`) in under 5 nanoseconds.

---

##### `security_policy`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pre_hook` | `string \| null` | `null` | Name of the pre-hook callback function (called *before* the original function). Must be tagged with `// @<name>-start` in the logic file. |
| `post_hook` | `string \| null` | `null` | Name of the post-hook callback function (called *after* the original function). Must be tagged with `// @<name>-start` in the logic file. |

Pre-hook and post-hook callback parameters are automatically extracted from the logic file via `libclang`. The transpiler validates that each callback parameter name matches a parameter of the target function. Policy authors can use the `__hook_result` wildcard in telemetry conditions and log format strings (e.g. `{__hook_result}`) to reference the return value returned from non-void target functions.

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
      log_rules:
        - arguments:
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
      log_rules:
        - arguments:
            - taskId
            - status
      security_policy:
        pre_hook: GenericEnterLog
        post_hook: LogTaskResult_post
```



## Template Architecture

The template system uses Jinja2's `{% include %}` mechanism to compose engine-specific templates from shared partial templates, allowing each engine to define its own hook installation/removal logic.

### Template Files

#### `detours_template.cpp`

The Detours template. Generates a complete DLL source file that:

- Includes Windows headers and `<detours.h>`.
- Defines the `HookActiveThreads` RAII struct for tracking in-flight hook executions.
- Includes `_user_logic_helpers.cpp` (which itself `#include`s the user's logic file).
- For each hook: generates a `typedef` for the original function pointer type, a static `True<FunctionName>` pointer, and a `Hooked<FunctionName>` function that includes `_hook_body.cpp`.
- Implements `EnlistAllThreads()` to enumerate process threads for Detours' thread-update mechanism.
- Exports `InitializeHooks()`: resolves target addresses, begins a Detours transaction, attaches all hooks, commits.
- Exports `DeinitializeHooks()`: begins a transaction, detaches all hooks, commits, spin-waits for in-flight executions.
- Includes `_dllmain.cpp`.

#### `frida_template.cpp`

The top-level Frida-Gum template. Structurally parallel to the Detours template, but utilizes Frida-Gum APIs:

- Includes `"frida-gum.h"`.
- Uses `gum_interceptor_replace()` for standard returning functions and `gum_interceptor_replace_fast()` for non-returning functions (`is_noreturn: true`).
- Conditionally uses `HookActiveThreads` RAII counter for non-returning functions to track active execution without interfering with Frida's invocation stack.
- `InitializeHooks()` calls `gum_init_embedded()` and obtains a `GumInterceptor`.
- `DeinitializeHooks()` uses a dual ejection check (`gum_interceptor_flush()` + `g_ActiveHooks.load() == 0`) before unreferencing the interceptor and calling `gum_deinit_embedded()`.

#### `_hook_body.cpp` (Shared Partial)

Generates the body of each `Hooked<FunctionName>` function. This is included once per hook within a `{% for hook in hooks %}` loop. It generates:

1. **Argument capture on entry**: For each logged argument, captures the value before the original call
2. **Performance timing start**: If `execution_time` is enabled, queries `QueryPerformanceCounter`.
3. **Pre-hook invocation**: If a `pre_hook` is defined, calls `RunPreLogic_<name>(...)`.
4. **Original function call**: Calls `True<FunctionName>(...)` via the trampoline pointer, capturing the return value in `__hook_result`.
5. **Post-hook invocation**: If a `post_hook` is defined, calls the post-hook function, passing target function parameters.
6. **Performance timing end**: Computes elapsed milliseconds, if specified.
7. **Argument capture on exit**: Re-captures logged arguments to detect mutations.
8. **Telemetry output**: Builds a log line with thread ID, argument values (showing `original -> mutated` for changed values), and latency.
9. **Return**: Returns `__hook_result` (or void).

#### `_user_logic_helpers.cpp` (Shared Partial)

Provides utility functions and SEH-protected wrappers included at the top of every generated file:

- `#include "{{ logic_file_rel }}"` — includes the user's logic file.
- `CopyString` — string copy helper to safely inspect `char*` pointers.
- `ReadPointer` — templated pointer dereference helper returning a fallback value if the pointer is null.

User callbacks (`pre_hook` and `post_hook`) are invoked directly within the `try { ... } catch (...)` exception blocks in `_hook_body.cpp` without wrapper indirection.

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
| `parameters` | List of parameter dicts with `type`, `name`, `pointer_depth`, `underlying_type`, `is_char_ptr`, `is_deref`, `safe_read_expr`, `safe_type` |
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


### Frida Attaching Modes & Thread Synchronization

HookDesigner supports dual Frida-Gum attaching modes based on the function return behavior specified in the YAML policy (`is_noreturn`):

#### 1. Standard Attaching Mode (`gum_interceptor_replace`)
- **Target Functions**: Standard functions that return to the caller (`is_noreturn: false`).
- **Mechanism**: Calls `gum_interceptor_replace(interceptor, target, replacement, nullptr, &original)`. Frida wraps execution with its full invocation listener/trampoline infrastructure.
- **Ejection Tracking**: Frida's native `gum_interceptor_flush(interceptor)` tracks active invocation frames on Frida's internal stack. During `DeinitializeHooks()`, calling `gum_interceptor_flush()` ensures all in-flight calls exit before unloading the DLL.

#### 2. Fast Attaching Mode (`gum_interceptor_replace_fast`)
- **Target Functions**: Non-returning functions marked with `is_noreturn: true` (e.g., `RaiseException`, `ExitProcess`, `longjmp`).
- **Mechanism**: Calls `gum_interceptor_replace_fast(interceptor, target, replacement, &original)`. Frida emits a direct inline jump to the hook wrapper without the overhead of Frida's invocation stack wrapper.
- **Use Case**: Eliminates latency for critical non-returning calls and prevents Frida's call-stack unwinding wrappers from being corrupted by functions that never return.

#### Hybrid Active Thread Synchronization (`HookActiveThreads`)

Because `gum_interceptor_replace_fast` bypasses Frida's native invocation stack wrappers, Frida's `gum_interceptor_flush()` alone cannot detect when threads are executing inside pre-hook logic for non-returning functions.

To solve this, HookDesigner implements a **hybrid RAII thread tracking pattern**:
- **Selective Declaration**: `HookActiveThreads` and `g_ActiveHooks` are declared conditionally in `_user_logic_helpers.cpp` (`need_active_counter = (engine == 'detours') or has_noreturn`).
- **Selective Guard Instantiation**: Inside `Hooked<FunctionName>`, `HookActiveThreads hook_active_threads;` is instantiated **only** for `is_noreturn: true` hooks when targeting Frida (and for all hooks when targeting Detours). Standard returning Frida hooks incur **zero thread-counter overhead**.
- **Disarm on Delegate**: Prior to invoking the original non-returning function (`True<FunctionName>(...)`), `hook_active_threads.Release()` explicitly decrements `g_ActiveHooks--`. If an exception or early return occurs during pre-logic, the RAII destructor automatically fires to decrement `g_ActiveHooks--`.
- **Dual Ejection Check**: In `DeinitializeHooks()`, when non-returning functions are present (`has_noreturn`), the flush loop waits for **both** `gum_interceptor_flush(interceptor)` AND `g_ActiveHooks.load() == 0`:
  ```cpp
  while (GetTickCount() - start < 2000) {
      if (gum_interceptor_flush(interceptor) && g_ActiveHooks.load() == 0) {
          g_Ejected = true;
          break;
      }
      Sleep(50);
  }
  ```


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

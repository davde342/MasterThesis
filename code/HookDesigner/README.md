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
   - [Telemetry Expressions & Pointer Dereferencing Safety](#telemetry-expressions--pointer-dereferencing-safety)
4. [Template Architecture](#template-architecture)
   - [Key Constants & Safety Bounds Rationale](#key-constants--safety-bounds-rationale)
5. [Hooking Engine Abstraction](#hooking-engine-abstraction)
6. [Build & Usage Guide](#build--usage-guide)
7. [Limitations & Future Work](#limitations--future-work)
8. [Dependencies](#dependencies)

---

## Project Structure

```
HookDesigner/
├── transpiler.py              # Core transpiler
├── injector.cpp               # C++ DLL injector (inject/eject/launch modes)
├── scada_engine.cpp           # SCADA simulator target with exported hookable functions
├── engines.yaml               # Engine registry: maps engine names to templates, libs, args
├── requirements.txt           # Python dependencies
├── .env.example               # Template for local environment paths (MSVC, Detours, Frida, Telemetry)
│
├── templates/                 # Jinja2 C++ template files
│   ├── detours_template.cpp   # Detours engine template (includes sub-templates)
│   ├── frida_template.cpp     # Frida-Gum engine template
│   ├── _hook_body.cpp         # Shared hook body: arg capture, pre/post logic, timing execution
│   ├── _telemetry_globals.cpp # Global exposer/registry pointers, headers, ToLabelString overloads
│   ├── _telemetry_init.cpp    # Spdlog thread pool / sink init and Prometheus exposer/metric family registration
│   ├── _telemetry_body.cpp    # Runtime log rule evaluation and Prometheus metric counter/gauge/histogram updates
│   ├── _dllmain.cpp           # Shared DLL entry point (DllMain)
│   └── _user_logic_helpers.cpp# Shared helpers (SEH ReadPointer, CopyString, thread tracking)
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
| `--arch` | `x64` | Target binary architecture (`x64` or `x86`) |
| `--libclang` | `$LIBCLANG_PATH` | Path to `libclang.dll` file or containing directory |
| `--vcvars` | `auto` | Path to MSVC's `vcvars` script (defaults to `$VCVARS64_PATH` or `$VCVARS32_PATH` based on `--arch`) |
| `--spdlog-include` | `$SPDLOG_INC` | Path to `spdlog` header include directory |
| `--prometheus-include` | `$PROMETHEUS_INC` | Path to `prometheus-cpp` include directory |
| `--prometheus-libs` | `auto` | Comma-separated paths to `prometheus-cpp` static `.lib` files (defaults to `$PROMETHEUS_LIBS_X64` or `$PROMETHEUS_LIBS_X86` based on `--arch`) |
| `--rt-link` | `/MT` | MSVC runtime linking model (`/MT` static or `/MD` dynamic) |
| `--gen-only` | `false` | Only render C++ without compiling |
| `--compile-only` | `false` | Only compile existing C++ without parsing/generating |
| `--validate-only` | `false` | Only validate the policy YAML |

> [!NOTE]
> **Compiler Options**: When invoking MSVC `cl.exe`, the transpiler applies `/LD` (DLL generation), `/EHa` (asynchronous SEH structured exception handling to catch memory violations during string copying or pointer dereferencing), `/O2` (optimization), `/Zi` and `/FS` (PDB debug symbols), `/utf-8` (character encoding), `/std:c++17` (C++17 language standard), and automatically links required Windows system libraries including `ws2_32.lib` and `crypt32.lib` when Prometheus metrics are enabled.

#### Features

1. **libclang for signature extraction**: Rather than using fragile regex-based C++ parsing, the transpiler creates an in-memory translation unit via `libclang` with a Windows-macro preamble (defining `WINAPI`, `CALLBACK`, etc.) and parses the AST. This correctly handles complex types, pointer nesting, and calling conventions.

2. **Tag-based convention for user logic**: The user's logic file uses comment-based markers (`// @signatures-start`, `// @FunctionName-start`) to delineate regions. This avoids requiring a custom parser or build system — the file is simultaneously a valid C++ header (included via `#include` in the generated code) and a structured input to the transpiler.

3. **Separation of policy from logic**: The YAML policy specifies *what* to hook and *which behaviors* to apply, while the C++ logic file specifies *how* (the actual callback implementations). This separation allow user to write C++ code in a usual code editor with syntax highlighting/intellisense enabled. It also enables the same logic file to be reused across different policies and engines.

4. **Sensible Defaults & Telemetry Expression Parsing**: Standalone function parameter references (`input_<param>`, `output_<param>`) in log rules and metric conditions or values are automatically analyzed via AST and wrapped in safe memory dereferencing primitives (`ReadPointer`). Arbitrary C++ expressions, casts, and pointer member access paths (`->`) are also supported. See [Telemetry Expressions & Pointer Dereferencing Safety](#telemetry-expressions--pointer-dereferencing-safety) for full details.

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
#### Features

1. **Separate `InitializeHooks` and `DeinitializeHooks` call**: Rather than attaching/detaching hooks in `DllMain` (which runs under the OS loader lock and has severe restrictions on what APIs can be called), the injector explicitly calls the exported `InitializeHooks` function via a second remote thread after injection completes. This avoids loader-lock deadlocks. Similarly, `DeinitializeHooks` is called before unloading the DLL to ensure a clean exit.

2. **Launch mode with `CREATE_SUSPENDED`**: The launch mode creates the target process in a suspended state, injects the DLL and installs hooks *before* the process's main thread runs. This guarantees hooks are active from the very first function call, which is critical for intercepting initialization-time behavior.

3. **Thread-Safe Ejection & Memory Leak Safety Fallback**: When ejecting a DLL (`injector.exe eject`), target threads might remain executing inside hooked callback functions or blocked on the target function (frequent with blocking functions, e.g. `recv()`, `Sleep()`, `WaitForSingleObject()`). Ejection is handled via a 2-tier safety mechanism:
   - **Hook Teardown & Spin-Wait Timeout**: Inside the Hook DLL, `DeinitializeHooks` immediately reverts all active hooks so no new threads enter hook routines. It then enters a 2-second spin-wait loop checking if active threads inside hook bodies reach zero.
     - **Clean Exit (`TRUE`)**: If all threads exit within 2 seconds, logger/metrics registries (`spdlog::shutdown()`, Prometheus) and TLS indexes are cleanly freed, and `DeinitializeHooks` returns `TRUE` (`1`).
     - **Ejection Failure (`FALSE`)**: If threads remain trapped in hook routines after 2 seconds, `DeinitializeHooks` skips logger/metrics destruction (preventing crash access violations for threads still running logging logic), logs a warning via `OutputDebugStringA`, and returns `FALSE` (`0`).
   - **Injector Fallback Strategy**: Upon receiving `FALSE` from `DeinitializeHooks`, the injector logs a warning and **deliberately skips calling `FreeLibrary`**. Leaking the DLL in target memory prevents the target process from access violation crashes if blocked threads eventually unblock and attempt to execute code in unmapped memory.

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
| `telemetry` | `object` | No | `null` | Global telemetry and metrics configuration (logging framework and Prometheus metrics exposition). |

#### `telemetry` Object

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `logger` | `string` | No | `null` | Logging framework (`"spdlog"` or omitted). |
| `logger_config` | `object` | No | `{}` | Logger sink and format configuration. |
| `metrics` | `string` | No | `null` | Metrics framework (`"prometheus"` or omitted). |
| `metrics_config` | `object` | No | `{}` | Prometheus HTTP exposer endpoint configuration. |

##### `logger_config`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `string` | `"file"` | Log sink type: `"udp"` (for remote logging) or `"file"` (for disk file sink). |
| `host` | `string` | `"127.0.0.1"` | Target host IP address for UDP Syslog sink. |
| `port` | `integer` | `1514` | Target UDP port for Syslog formatted logs. |
| `file` | `string` | `"hook_log.txt"` | Output log file path when `type: "file"`. |
| `level` | `string` | `"info"` | Global log severity filter level (`"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`, `"critical"`). |

##### `metrics_config`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | `string` | `"127.0.0.1:8080"` | Prometheus HTTP Exposer listening address and port (e.g. `"0.0.0.0:8085"`). |

---

### `hooks` Section

A list of hook definitions. Each hook specifies a target function and its associated behaviors.

#### Hook Object

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `function_name` | `string` | **Yes** | — | Name of the target function to hook (must match a signature in the logic file). |
| `is_noreturn` | `bool` | No | `false` | Explicit flag indicating that the function never returns (e.g. `ExitProcess`, `RaiseException`, `ExitThread`). Inferred automatically for known functions (`RaiseException`, `ExitProcess`, `ExitThread`). Enables fast attaching mode in Frida-Gum for correctly adjusting thread-tracking RAII cleanup for this type of functions. |
| `module` | `string` | No | `""` | Name of the DLL/EXE module containing the target function. If empty, uses the main process module. |
| `address_resolution` | `object` | No | `{strategy: "export"}` | How to resolve the function's address at runtime. See below. |
| `behaviors` | `object` | No | `{}` | Behavioral policies to apply to this hook. See below. |

#### `address_resolution` Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `strategy` | `string` | **Yes** | Resolution strategy: `"export"` (via `GetProcAddress`) or `"offset"` (via base address + RVA). |
| `symbol_name` | `string` | No | Exported symbol name used by `GetProcAddress` (default: `function_name`). Allows hooking exported symbols with mangled/decorated C++ names or exported aliases differing from the DSL function name. |
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
| `execution_time` | `bool` | `false` | If `true`, measure target function execution latency using `QueryPerformanceCounter`, enabling the `__hook_latency` wildcard (in milliseconds) for use in metric values, conditions, and log format strings. |
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
| `value` | `string` | **Gauges & Histograms** | — | C++ telemetry expression to observe or set (e.g., `__hook_latency`, `input_<param>`, `output_<param>`, `__hook_result`, or a valid c++ variable). |
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
      value: "__hook_latency"
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
```
###### Metrics Performance Guidelines

When designing metrics (Counters, Gauges, Histograms) for high-frequency or hot-path hooked functions (e.g., `EnterCriticalSection`, `ReadFile`, `WaitForSingleObject`), adhere to the following practices:

1. **Validation & Low-Cardinality Metric Labels**:
   - Avoid using high-cardinality dynamic variables (such as thread IDs `{__hook_tid}`, pointer addresses `{input_buf_ptr}`, or timestamps) inside Prometheus metric label expressions.
   - Prometheus documentation explicitly state: *“Labels should only be used for low-cardinality dimensions (e.g. HTTP status codes, error types, method names).”* High-cardinality values belong in **logs**, not metric labels.

2. **Thread-Local / Direct Metric Caching**:
   - For hooks with dynamic low-cardinality labels, HookDesigner automatically utilizes a `thread_local static` metric cache.
   - The first invocation for a given label set fetches the metric reference from `prometheus::Family::Add()`, while subsequent calls on the same thread bypass Prometheus's internal `std::mutex` lock, achieving near zero-cost updates on the hot path.

3. **Promote Label-less Counters for Hot Paths**:
   - For extremely high-frequency functions, prefer label-less counters. Label-less metrics use direct global references (`g_PromMetric_->Increment()`) which perform lock-free atomic updates (`std::atomic<double>`).

##### `log_rules`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | `"rule_N"` | Name identifier for the log rule (auto-generated as `rule_1`, `rule_2`, etc. if omitted). |
| `condition` | `string` | `"true"` | Boolean C++ telemetry expression evaluated to determine if log fires. |
| `level` | `string` | `"info"` | Log level (`trace`, `debug`, `info`, `warn`, `error`, `critical`). |
| `arguments` | `list[string]` | `[]` | List of parameter names (`input_<param>` or `output_<param>`) or reserved hook variables (`__hook_result`, `__hook_latency`, `__hook_tid`) to capture for auto-generated format strings. |
| `format` | `string` | `null` | Custom log format string supporting placeholders (`{__hook_tid}` (thread id), `{__hook_latency}`, `{__hook_result}`, `{input_<param>}`, `{output_<param>}`, or any valid C++ `{variable/expression}`). |

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
   Defines an explicit log message format using placeholders like `{__hook_tid}`, `{__hook_result}`, `{input_<param>}`, or `{output_<param>}` (with optional C++ format specifiers like `:x`):
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
  - Every argument name must start with `input_` or `output_` matching a valid function parameter (e.g. `input_lpSubKey`), or be a reserved hook variable (`__hook_result`, `__hook_latency`, `__hook_tid`).
- **Format String Placeholders**: Placeholders inside `format` strings can reference:
  - `{__hook_tid}` (Thread ID)
  - `{__hook_latency}` (Execution time in milliseconds)
  - `{__hook_result}` (Return value of the hooked function)
  - `{input_<param>}` or `{output_<param>}` (Target function parameters)
  - Custom C++ expressions, struct fields (e.g. `{input_pStruct->field}`), or local variables declared in `pre_hook` / `post_hook` callbacks.
  - Placeholders support C++ format specifiers following a colon (e.g., `{input_samDesired:x}`).
- **Telemetry Requirement**: If `log_rules` are present on any hook, top-level `configure.telemetry` must be configured (e.g., `logger: spdlog`).

##### Telemetry Expressions & Pointer Dereferencing Safety

When writing C++ telemetry expressions in `log_rules` (conditions, custom formats, arguments) or `performance_metrics` (metric conditions, gauge/histogram values, dynamic label expressions), the transpiler balances memory safety and flexibility through defaults and an explicit escape mechanism:

- **Defaults (Automatic Safe Memory Reads)**: Referencing standalone parameter variables (e.g., `input_paramName` or `output_paramName`) automatically generates type-safe memory reads using `ReadPointer(...)` or safe string copying based on static type analysis from `libclang` (see `safe_read_expr` and `safe_type` under [Parameter Dictionary Fields](#parameter-dictionary-fields)). Policy authors do not need to write explicit dereference primitives for standalone parameters.

- **Escape mechanism & Flexible Expressions**: Policy authors can write arbitrary C++ expressions, custom local variables (declared in `pre_hook` / `post_hook`), address-of operators (`&`), global atomic variables, or explicit C++ casts.

> [!IMPORTANT]
> **Member Access Bypasses Automatic Type Analysis:** When accessing struct or class fields of a parameter (e.g., `input_pStruct->field` or `input_pStruct.field`), the transpiler detects member access (`->` or `.`) and **bypasses all automatic `libclang` type transformations**. None of the automatic protections generated for standalone parameters (such as `ReadPointer(...)` pointer dereferencing or `CopyString(...)` safe string copying) are applied. In this case, **the policy author must explicitly handle memory safety manually** (e.g., wrapping pointer field reads in `ReadPointer(input_pStruct->pInt)` or string fields in `CopyString(input_pStruct->szName)` — defined in [`_user_logic_helpers.cpp`](file:///c:/Users/davig/Desktop/Thesis/Code/MasterThesis/code/HookDesigner/templates/_user_logic_helpers.cpp)).

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
  process: ApmsrtDIP.exe
  logic_file: "test_queue.cpp"
  telemetry:
    logger: "spdlog"
    logger_config:
      type: "udp"
      host: "192.168.88.1"
      port: 1514
      level: "info"
    metrics: "prometheus"
    metrics_config:
      endpoint: "0.0.0.0:8085"

hooks:
  - module: Uti109064.dll
    function_name: QueuePut
    address_resolution:
      strategy: export
      symbol_name: "?Put@CLogQueue@@QEAAHPEAULOG_QENTRY@@@Z"
    behaviors:
      performance_metrics:
        execution_time: true
        counters:
          - name: "queue_put_total"
            description: "Total QueuePut calls across all queues"
            label:
              queue_id: "input_pQueue.queueId"
          - name: "queue_put_success"
            description: "Successful QueuePut calls"
            condition: "__hook_result == 0"
            label:
              queue_id: "input_pQueue.queueId"
        histograms:
          - name: "queue_put_latency"
            description: "Distribution of QueuePut execution times"
            value: "__hook_latency"
            label:
              queue_id: "input_pQueue.queueId"
      log_rules:
        - name: "queue_put_failed"
          condition: "__hook_result != 0"
          level: "warn"
          format: "[WARN] PUTQ FAILED | queue_id={input_pQueue.queueId} result={__hook_result}"
      security_policy:
        pre_hook: QueuePut_pre

  - module: kernel32.dll
    function_name: RaiseException
    is_noreturn: true
    address_resolution:
      strategy: export
    behaviors:
      log_rules:
        - name: "raise_exception"
          level: "error"
          format: "[RaiseException] Exception raised Code: 0x{input_dwExceptionCode:x}, Flags: 0x{input_dwExceptionFlags:x}"
```

---

## Template Architecture

The template system uses Jinja2's `{% include %}` mechanism to compose engine-specific templates from shared partial templates, allowing each engine to define its own hook installation/removal logic.

### Template Files

#### `detours_template.cpp`

The template for the Microsoft Detours engine. It generates a self-contained C++ source file implementing hooks specified in the YAML policy:

- **Hooking Paradigm**: Uses Microsoft Detours' inline prologue patching mechanism (`DetourAttach` / `DetourDetach`). Overwrites the first 5+ bytes of the target API function prologue with a relative `JMP` instruction to `Hooked<FunctionName>`, allocating a trampoline stub (`True<FunctionName>`) containing the original prologue instructions and a jump back to the real function.

- **Attaching Procedure (`InitializeHooks()`)**:
  1. Allocates a Thread Local Storage (TLS) index via `TlsAlloc()` for recursion guarding (`RecursionHookGuard`).
  2. Initializes telemetry globals and metrics servers via `_telemetry_init.cpp`.
  3. Resolves target function virtual addresses using module handle lookup and `GetProcAddress`.
  4. Enumerate process worker threads via `EnlistAllThreads()` (using `CreateToolhelp32Snapshot`).
  5. Opens a Detours transaction via `DetourTransactionBegin()`.
  6. Registers all worker threads with `DetourUpdateThread()`.
  7. Attaches each target function via `DetourAttach(&(PVOID&)True<FunctionName>, Hooked<FunctionName>)`.
  8. Commits the transaction with `DetourTransactionCommit()` and closes thread handles.

- **Detaching Procedure (`DeinitializeHooks()`)**:
  1. Stops background HTTP metric servers (`g_PromExposer.reset()`) to terminate active web worker threads cleanly.
  2. Enumerate process threads via `EnlistAllThreads()`.
  3. Opens a Detours transaction (`DetourTransactionBegin()`), calls `DetourUpdateThread()` for each worker thread, and detaches all target functions via `DetourDetach()`.
  4. Commits the transaction via `DetourTransactionCommit()`, reverting target API prologues to original bytes.

- **Thread Safety & Ejection Synchronization**:
  - **Attach/Detach Thread Safety**: Uses `EnlistAllThreads()` combined with `DetourUpdateThread()` to pause and adjust worker thread execution states during prologue byte modification.
  - **Ejection Guard**: Every hook wrapper unconditionally instantiates a `HookActiveThreads` RAII counter on entry, which atomically increments `activeThreads` on construction and decrements it on destruction. During `DeinitializeHooks()`, after detaching API hooks, the DLL executes a 2-second spin-wait loop checking `activeThreads.load() == 0` (to avoid DLL unload while worker threads are still within the hook logic). Once confirmed zero, telemetry loggers (`spdlog::shutdown()`) and TLS slots are safely destroyed before DLL unloading.

#### `frida_template.cpp`

The top-level template for the Frida-Gum engine. Utilizes Frida's dynamic binary instrumentation runtime (`"frida-gum.h"`):

- **Hooking Paradigm**: Uses Frida-Gum dynamic code allocation and interceptor replacement (`gum_init_embedded()`, `GumInterceptor`). It supports dual attaching modes based on the function return policy (`is_noreturn`).

- **Attaching Procedure (`InitializeHooks()`)**:
  1. Allocates a TLS index via `TlsAlloc()` for recursion guarding (same as Detours).
  2. Initializes telemetry globals, initializes embedded Frida-Gum (`gum_init_embedded()`), and obtains a `GumInterceptor` handle via `gum_interceptor_obtain()`.
  3. Resolves target function addresses.
  4. Opens an atomic Frida transaction via `gum_interceptor_begin_transaction(interceptor)`.
  5. Replaces target functions based on return behavior:
     - **Standard Functions** (`is_noreturn: false`): Calls `gum_interceptor_replace()`, enabling Frida's invocation listener stack tracking for thread ejection via `gum_interceptor_flush()`.
     - **Non-Returning Functions** (`is_noreturn: true`, e.g. `ExitProcess`, `ExitThread`, `RaiseException`): Calls `gum_interceptor_replace_fast()`. Standard `gum_interceptor_replace()` pushes an invocation frame on entry and expects to pop it on function exit; because non-returning functions never return, Frida's listener frame is never popped, which would cause `gum_interceptor_flush()` to hang indefinitely or fail. Using `gum_interceptor_replace_fast()` bypasses Frida's invocation listener stack, adopting a direct replacement model (similar to Detours) that relies on the `HookActiveThreads` RAII counter instead.
  6. Commits the transaction via `gum_interceptor_end_transaction(interceptor)`, applying all trampoline modifications atomically.

- **Detaching Procedure (`DeinitializeHooks()`)**:
  1. Stops background HTTP metric servers (`g_PromExposer.reset()`).
  2. Opens a transaction (`gum_interceptor_begin_transaction()`), reverts all hook replacements via `gum_interceptor_revert()`, and commits the transaction (`gum_interceptor_end_transaction()`).

- **Thread Safety & Ejection Synchronization**:
  - **Attach/Detach Thread Safety**: Uses Frida's native transaction block (`gum_interceptor_begin_transaction` / `end_transaction`) which applies atomic instruction patching across memory pages without manual `SuspendThread`, avoiding the Windows NT heap-lock deadlock hazard.
  - **Dual Ejection Synchronization**: Standard returning functions rely on `gum_interceptor_flush(interceptor)` to verify that zero active invocation frames remain on Frida's internal listener stack. Non-returning functions use the `HookActiveThreads` RAII counter (`activeThreads`) to track thread trapped within the hook logic . `DeinitializeHooks()` executes a 2-second spin-wait loop performing a dual check: `if (gum_interceptor_flush(interceptor) && activeThreads.load() == 0)`. Once both checks confirm zero active threads, `g_object_unref(interceptor)` and `gum_deinit_embedded()` are called, followed by telemetry destruction (`spdlog::shutdown()`).

#### `_hook_body.cpp` (Shared Partial)

Generates the body of each `Hooked<FunctionName>` function wrapper. Included once per hook within a `{% for hook in hooks %}` loop. It generates:

1. **Argument capture on entry**: Captures parameter values referenced in telemetry expressions before invoking the original function. Standalone parameter references are accessed as `input_<parameter_name>` (using `ReadPointer` for pointer types or `CopyString` for string pointers). 
2. **Performance timing start**: Queries `QueryPerformanceCounter` if `execution_time` is enabled.
3. **Pre-hook invocation**: Calls user `pre_hook` callback within `try { ... } catch (...)` exception blocks.
4. **Original function call**: Calls `True<FunctionName>(...)` via the trampoline pointer, capturing the return value in `__hook_result`.
5. **Post-hook invocation**: Calls user `post_hook` callback.
6. **Performance timing end**: Computes elapsed milliseconds latency.
7. **Argument capture on exit**: Re-captures parameters if referenced, in the policy, they are indicated as `output_<parameter_name>`. 
8. **Telemetry execution**: Includes `_telemetry_body.cpp` to evaluate log rules and record metrics.
9. **Return**: Returns `__hook_result` (or void).

#### `_telemetry_globals.cpp` (Shared Partial)

Generates global pointers, headers, and helper overloads for telemetry components:

- Includes headers for `spdlog` (async logger, file/udp sinks) and `prometheus-cpp` (exposer, registry, counter, gauge, histogram).
- Defines global pointers `g_PromExposer` and `g_PromRegistry`.
- Declares metric family pointers (`g_PromFamily_<func>_<metric>`) and static metric handles (`g_PromMetric_<func>_<metric>`) for label-less metrics.
- Provides overloaded `ToLabelString(...)` helper functions for converting string literals, primitive types (`int`, `double`), and custom C++ expressions into Prometheus label strings.

#### `_telemetry_init.cpp` (Shared Partial)

Generates initialization code invoked inside `InitializeHooks()`:

- Initializes high-resolution timer frequency (`QueryPerformanceFrequency`).
- Configures `spdlog` thread pool (`init_thread_pool`) and creates an asynchronous UDP Syslog sink (formatted with RFC-5424 timestamp) or basic file sink.
- Instantiates `prometheus::Exposer` listening on the configured HTTP endpoint and registers `prometheus::Registry`.
- Builds and registers all Prometheus metric families (`BuildCounter()`, `BuildGauge()`, `BuildHistogram()`) and adds label-less metric handles to the registry.

#### `_telemetry_body.cpp` (Shared Partial)

Generates runtime telemetry evaluation logic inside each `Hooked<FunctionName>` wrapper:

- Evaluates log rules against runtime conditions and emits logs via `spdlog` (or `fmt::format`).
- Evaluates counter, gauge, and histogram metric conditions.
- Handles dynamic metric labels using trivial thread-local POD caching (`uint64_t` hash and pointer caching) for high-performance lock-free lookup on hot execution paths without dynamic TLS destructor overhead.

#### `_user_logic_helpers.cpp` (Shared Partial)

Provides utility functions and SEH-protected wrappers included at the top of every generated file:

- `#include "{{ logic_file_rel }}"` — includes the user's logic file.
- `RecursionHookGuard` — TLS-based thread guard to prevent re-entrant hook loops.
- `HookActiveThreads` — RAII thread tracking counter (`activeThreads`) for safe ejection.
- `CopyString` — safe string copy helper using SIMD `strnlen` to inspect `char*` pointers up to a max length without crash risks; memory access violations are caught by `/EHa` structured exception handling.
- `ReadPointer` — templated pointer dereference helper returning a fallback value if the pointer is null or unmapped; protected against access violations via `/EHa`structured exception .

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
| `telemetry` | `dict` | Enriched global telemetry configuration (logger framework, logger config, metrics framework, metrics config, execution timing flag) |

The `telemetry` object contains:

| Field | Type | Description |
|-------|------|-------------|
| `logger` | `string \| null` | Configured logger framework (e.g. `"spdlog"`, or `null`) |
| `logger_config` | `dict` | Sink and log level configuration (`type`, `host`, `port`, `file`, `level`) |
| `metrics` | `string \| null` | Configured metrics framework (e.g. `"prometheus"`, or `null`) |
| `metrics_config` | `dict` | Metrics endpoint configuration (`endpoint`) |
| `has_execution_time` | `bool` | `true` if execution timing is enabled on any defined hook |

Each `hook` object within `hooks` contains the fields from the YAML schema plus transpiler-enriched fields:

| Field | Description |
|----------------|-------------|
| `parameters` | List of parameter dicts (see detailed parameter key breakdown below) |
| `return_type` | C++ return type string |
| `calling_convention` | Detected calling convention if specified (e.g., `"__stdcall"`, `""`) |
| `address_resolution_cpp` | Generated C++ expression for resolving the function address |

#### Parameter Dictionary Fields

Each element in `hook.parameters` is a dictionary describing a function parameter with transpiler-enriched metadata:

| Key | Type | Description |
|-----|------|-------------|
| `name` | `string` | Parameter variable identifier in the C++ function signature |
| `type` | `string` | Original C++ type declaration (e.g., `LPCSTR`, `int*`) |
| `is_char_ptr` | `bool` | `true` if parameter is a C-string pointer (`char*`, `LPCSTR`, `wchar_t*`, etc.) |
| `safe_read_expr` | `string` | Generated C++ expression to safely read memory (e.g., `ReadPointer(...)`, `CopyString(...)`, or raw parameter) |
| `safe_type` | `string` | Appropriate C++ type for storing/logging the value (e.g., `std::string` for string pointers) |

### Key Constants & Safety Bounds Rationale

HookDesigner relies on specific numerical constants across its templates for ejection synchronization, queue sizing, and memory bounds. Below is the technical rationale and safety trade-off for each value:

#### 1. `2000 ms` — Total Drain Budget ($T_{\text{drain}}$)
- **Source**: [`detours_template.cpp`](templates/detours_template.cpp#L258), [`frida_template.cpp`](templates/frida_template.cpp#L212)
- **Rationale**: This budget is not designed to outlast a worst-case blocking call (e.g., a `recv()` call that could block for minutes — that is precisely what the controlled DLL leak fallback handles, not this timer). Instead, it acts as a **classification threshold**: distinguishing "ordinary hook executions still finishing up" from "a thread is genuinely stuck inside a blocking target call." A normal hook body (pre-hook, trampoline call, post-hook, telemetry) completes within microseconds to a few milliseconds. 2,000 ms is comfortably longer than that, absorbing OS scheduling jitter on a heavily loaded host. If `activeThreads` has not reached zero after 2 seconds, it provides a reliable signal that a thread is blocked deep inside the trampoline, at which point waiting longer would not help and falling through to the safe-leak path is the right call. It also provides an operator or an automated ejection script with a bounded, predictable wait rather than hanging indefinitely.

#### 2. `1000 ms` — Confirmation Sleep
- **Source**: [`detours_template.cpp`](templates/detours_template.cpp#L260), [`frida_template.cpp`](templates/frida_template.cpp#L215)
- **Rationale**: This delay exists specifically to close a subtle race window during thread exit: `HookActiveThreads`'s destructor decrements `activeThreads` as the C++ stack unwinds, but a handful of epilogue machine instructions (register restoration, `ret`, and returning through the trampoline) still execute inside the DLL's mapped pages *after* that decrement and before the thread physically leaves the module. Unmapping the DLL the exact instant the counter hits zero risks a preempted thread faulting on now-unmapped memory mid-epilogue (`STATUS_ACCESS_VIOLATION`). The 1-second confirmation window comfortably outlasts that sliver of epilogue code even under severe scheduler contention on a multi-threaded host (where a worker thread can be preempted right at the worst possible instruction). Because ejection is not latency-critical (unlike hot-path hooking), waiting 1 extra second is a reasonable trade-off to eliminate this crash race.

#### 3. `50 ms` — Poll Interval
- **Source**: [`detours_template.cpp`](templates/detours_template.cpp#L266), [`frida_template.cpp`](templates/frida_template.cpp#L227)
- **Rationale**: This defines the loop's polling granularity and is the least safety-critical of the timing constants. It bounds how much the loop can overshoot the 2,000 ms budget (in the worst case, by at most one extra interval, ~50 ms) without busy-spinning and burning 100% CPU on an otherwise idle wait. Unlike the drain budget and confirmation window, nothing in the safety argument strictly depends on 50 ms specifically — any small, responsive polling interval would suffice (it is a convenience constant rather than correctness-load-bearing).

#### 4. `65,536` ($2^{16}$) — `spdlog` Async Queue Capacity
- **Source**: [`_telemetry_init.cpp`](templates/_telemetry_init.cpp#L7)
- **Rationale**: When critical hooked functions execute thousands of times per second across concurrent worker threads, each invocation can potentially emit multiple `log_rules`. The asynchronous queue must absorb worst-case bursts without blocking the producing worker thread while the background worker flushes records to disk or UDP Syslog. A power of two ($2^{16}$) enables lock-free ring-buffer implementations using cheap bitmask wrapping (`index & (size - 1)`) instead of expensive modulo arithmetic.

#### 5. `128` — `CopyString` Default `maxChars` Bound
- **Source**: [`_user_logic_helpers.cpp`](templates/_user_logic_helpers.cpp#L40), [`_user_logic_helpers.cpp`](templates/_user_logic_helpers.cpp#L49)
- **Rationale**: This is a safety bound rather than a completeness bound. It caps the worst-case cost of scanning a corrupted, or non-null-terminated string pointer on the hot execution path (SIMD `strnlen` and `wcsnlen` never inspect beyond 128 characters, regardless of buffer contents). The explicit engineering trade-off is **silent truncation**: an identifier, file path, or registry subkey (e.g., in `RegOpenKeyExA`) longer than 128 characters is truncated with no explicit indication in the emitted log.

---

## Hooking Engine Abstraction

### `engines.yaml` Registry

The engine registry is a YAML file that maps paradigm names to engine definitions. The registry can be easily extended with new paradigms/engines.

```yaml
inline_hook:
  detours:
    template: "detours_template.cpp"
    cast_format: "(True{name}_t)"
    include_path: "${DETOURS_INC}"
    lib_path: "${DETOURS_LIB_{ARCH}}"
    extra_libs:
      - "User32.lib"
      - "Advapi32.lib"

  frida:
    template: "frida_template.cpp"
    cast_format: "(gpointer)"
    include_path: "${FRIDA_INC_{ARCH}}"
    lib_path: "${FRIDA_LIB_{ARCH}}"
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
| `include_path` | Yes | Engine header include directory path. Supports `${VAR}` environment variable expansion and `{ARCH}` placeholder (resolved dynamically to `X64` or `X86` based on `--arch`). |
| `lib_path` | Yes | Engine static library (`.lib`) file path. Supports `${VAR}` environment variable expansion and `{ARCH}` placeholder (resolved dynamically to `X64` or `X86` based on `--arch`). |
| `extra_libs` | No (default `[]`) | Additional Windows `.lib` files or paths to link |

### Engine Selection Guidelines: Detours vs. Frida-Gum for Low-Level APIs

When instrumenting complex multithreaded Windows processes, selecting the appropriate engine is critical when intercepting frequently invoked, low-level Win32 synchronization primitives (`EnterCriticalSection`, `LeaveCriticalSection`, `WaitForSingleObject`, `ReleaseMutex`).

#### 1. The Instruction Pointer (`RIP`) Relocation Hazard in Live Processes
When inline hooks overwrite the prologue of high-frequency APIs in an actively running process:
- **Microsoft Detours (`detours_template.cpp`)**: Uses `EnlistAllThreads()` combined with `DetourUpdateThread()`. During `DetourTransactionCommit()`, Detours suspends active worker threads and calls `GetThreadContext()` to inspect each thread's instruction pointer (`RIP`). If a worker thread is paused mid-execution inside the first 5+ bytes of the prologue being overwritten, Detours **recalculates the instruction offset and updates `RIP` (`SetThreadContext`)** to point to the relocated instruction within the trampoline stub before resuming the thread.
- **Frida-Gum (`frida_template.cpp`)**: Applies atomic in-memory instruction patching within `gum_interceptor_begin_transaction` / `end_transaction`, but does **not** inspect or adjust the `RIP` registers of existing worker threads. If a background thread is currently executing the first few bytes of `EnterCriticalSection` during live patching, its `RIP` lands on a partial jump instruction. This mangles CPU registers (e.g., leaving `RBX` pointing to deallocated `MEM_FREE` memory), triggering an immediate `c0000005 ACCESS_VIOLATION`.

#### 2. The Memory Allocation Deadlock Hazard
Frida-Gum cannot safely solve this by blindly calling `SuspendThread()` across all worker threads:
- Frida-Gum's runtime is built on GLib (`g_malloc`, `g_slice`, etc.) and **dynamically allocates heap memory** during `gum_interceptor_replace()` and `gum_interceptor_end_transaction()`.
- If a worker thread is suspended while holding the NT Process Heap lock (`RtlAllocateHeap`), the injector thread will permanently deadlock when Frida tries to allocate memory.
- Microsoft Detours' core transaction engine was hand-crafted to avoid standard heap allocations during `DetourTransactionCommit()`, allowing safe thread suspension and `RIP` relocation without colliding with process heap locks.


---

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
   ```cmd
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

   # Telemetry Configuration (spdlog & prometheus-cpp)
   SPDLOG_INC=C:\Path\To\spdlog\include
   PROMETHEUS_INC=C:\Path\To\prometheus-cpp\core\include,C:\Path\To\prometheus-cpp\pull\include
   PROMETHEUS_LIBS=C:\Path\To\prometheus-cpp\lib\prometheus-cpp-core.lib,C:\Path\To\prometheus-cpp\lib\prometheus-cpp-pull.lib,C:\Path\To\prometheus-cpp\lib\civetweb.lib

   # LLVM/Clang libclang Path
   LIBCLANG_PATH=C:\Program Files\LLVM\bin
   ```

3. **Compile the SCADA simulator** (for simple testing):
   ```bat
   build_engine.bat
   ```

4. **Compile the injector** (using a Developer Command Prompt for VS):
   ```cmd
   cl.exe /EHsc /O2 injector.cpp /I"C:\Detours\include" "C:\Detours\lib.X64\detours.lib"
   ```

### Writing a Policy YAML

Create a YAML file that declares the target process, the logic file, the hooking engine(s), telemetry configuration, and the list of functions to hook with their behaviors. For a detailed reference see the [Policy YAML Schema](#policy-yaml-schema) section.

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
```cmd
python transpiler.py policy.yaml --output-cpp hook.cpp --output-dll hook.dll
```

**Generate C++ only** (no compilation):
```cmd
python transpiler.py policy.yaml --output-cpp hook.cpp --gen-only
```

**Validate policy only**:
```cmd
python transpiler.py policy.yaml --validate-only
```

**Multi-engine generation** (produces `hook_detours.cpp`, `hook_detours.dll`, `hook_frida.cpp`, `hook_frida.dll`):
```cmd
python transpiler.py policy.yaml --output-cpp hook.cpp --output-dll hook.dll
```
When the policy specifies multiple engines, output files are automatically suffixed with the engine name.

### Injecting the DLL

HookDesigner supports both 64-bit and 32-bit processes. The injector and target process must match in bitness (run `build_injectors.bat` to compile both `injector64.exe` and `injector32.exe`):

**For 64-bit targets (x64)**:
```cmd
python transpiler.py policy.yaml --arch x64 --output-dll hook.dll
injector64.exe inject <PID> hook.dll
```

**For 32-bit targets (x86)**:
```cmd
python transpiler.py policy.yaml --arch x86 --output-dll hook32.dll
injector32.exe inject <PID> hook32.dll
```

**Launch a new process with injection**:
```cmd
injector64.exe launch scada_engine.exe hook.dll
```

**Eject a previously injected DLL**:
```cmd
injector64.exe eject <PID> hook.dll
```

---

## Limitations & Future Work

HookDesigner currently focuses on the `inline_hook` paradigm (Microsoft Detours and Frida-Gum), providing low-overhead function-level API interception and telemetry generation. 

Future work focuses on extending HookDesigner to support **Dynamic Binary Instrumentation (DBI)** frameworks such as **Intel PIN** and **DynamoRIO**.

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
| **spdlog** | High-performance asynchronous logging (file & UDP Syslog) | Telemetry logger |
| **prometheus-cpp** | Prometheus HTTP metric exposition (counters, gauges, histograms) | Telemetry metrics |
| **fmt** | String formatting library for logs and debug output | Telemetry logger |
| **Windows SDK & System Libs** | Win32 APIs, Sockets (`ws2_32.lib`), Crypto (`crypt32.lib`), RPC (`Rpcrt4.lib`) | All components |
| **MSVC C++ Runtime** | Standard library, `/EHa` SEH support | All components |

### Build Tools

| Tool | Purpose |
|------|---------|
| **MSVC `cl.exe`** | C++ compiler for DLL generation |
| **`vcvars64.bat`** | Sets up the MSVC 64-bit build environment |

---

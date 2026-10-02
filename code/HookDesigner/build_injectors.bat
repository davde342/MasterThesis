@echo off
setlocal

rem Load environment variables from .env if present
if exist .env (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        set "line=%%A"
        if not "!line:~0,1!"=="#" (
            if not "%%B"=="" set "%%A=%%B"
        )
    )
)

if "%VCVARS64_PATH%"=="" (
    echo Error: VCVARS64_PATH is not set in environment or .env file.
    exit /b 1
)

if "%VCVARS32_PATH%"=="" (
    echo Error: VCVARS32_PATH is not set in environment or .env file.
    exit /b 1
)

echo ========================================================
echo Compiling injector64.exe (x64)
echo ========================================================
call "%VCVARS64_PATH%"
cl.exe /O2 /EHsc /utf-8 /std:c++17 injector.cpp /Fe:injector64.exe
if errorlevel 1 (
    echo Failed to build injector64.exe
    exit /b 1
)
if exist injector.obj del injector.obj

echo.
echo ========================================================
echo Compiling injector32.exe (x86)
echo ========================================================
call "%VCVARS32_PATH%"
cl.exe /O2 /EHsc /utf-8 /std:c++17 injector.cpp /Fe:injector32.exe
if errorlevel 1 (
    echo Failed to build injector32.exe
    exit /b 1
)
if exist injector.obj del injector.obj

echo.
echo ========================================================
echo Build complete: injector64.exe and injector32.exe ready.
echo ========================================================
endlocal

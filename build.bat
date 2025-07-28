@echo off
setlocal enabledelayedexpansion

:: Set output executable name
set OUTPUT=mass.exe

:: Find all .c files in current and subdirectories
set SRC_FILES=
for /r %%f in (*.c) do (
    set SRC_FILES=!SRC_FILES! "%%f"
)

:: Compile with GCC and link necessary libraries
echo Compiling...
gcc -O3 !SRC_FILES! -o %OUTPUT% -lcurl -lmicrohttpd -lsqlite3 -ljansson -lssl -lcrypto -lregex

:: Check if compilation was successful
if %errorlevel% neq 0 (
    echo Compilation failed!
    exit /b %errorlevel%
)

echo Compilation successful.
%OUTPUT%

endlocal
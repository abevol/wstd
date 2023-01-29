@ECHO OFF
CD /D %~dp0
SETLOCAL enabledelayedexpansion
cls
::COLOR B0

for /f "skip=2 delims=: tokens=1,*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v "ProgramFilesDir (x86)"') do ( 
    set str=%%i
    set var=%%j
    set "var=!var:"=!"
    if not "!var:~-1!"=="=" set strCMD=!str:~-1!:!var!
)
set strCMD=!strCMD!\Microsoft Visual Studio\Installer\vswhere.exe

if exist "!strCMD!" (
for /f "delims=" %%i in ('"!strCMD!" -nologo -version [17.0^,18.0] -prerelease -property installationPath -format value') do (
    set vsPath=%%i
    )
)
set vsPath=!vsPath!\VC\Auxiliary\Build\vcvarsall.bat
set vsvarbat="!vsPath!"
echo %vsvarbat%

set PLATFORM_TOOLSET=%1
set PLATFORM_VERSION=10.0

if DEFINED BUILD_TEST (
    set TARGET_PROJECTS=wstd;wstd_test
) else (
    set TARGET_PROJECTS=wstd
)

set PLATFORM_ARCH=x86
call !vsvarbat! %PLATFORM_ARCH%
if ERRORLEVEL 1 (
    echo call vsvarbat failed!
    goto final
)
set SLN_FILE="%CD%\wstd.sln"
MSBuild %SLN_FILE% /nologo /v:m /t:%TARGET_PROJECTS% /p:Configuration="Debug" /p:Platform=%PLATFORM_ARCH% /p:PlatformToolset=%PLATFORM_TOOLSET% /p:WindowsTargetPlatformVersion=%PLATFORM_VERSION%
MSBuild %SLN_FILE% /nologo /v:m /t:%TARGET_PROJECTS% /p:Configuration="Release" /p:Platform=%PLATFORM_ARCH% /p:PlatformToolset=%PLATFORM_TOOLSET% /p:WindowsTargetPlatformVersion=%PLATFORM_VERSION%
MSBuild %SLN_FILE% /nologo /v:m /t:%TARGET_PROJECTS% /p:Configuration="ReleaseMT" /p:Platform=%PLATFORM_ARCH% /p:PlatformToolset=%PLATFORM_TOOLSET% /p:WindowsTargetPlatformVersion=%PLATFORM_VERSION%

set PLATFORM_ARCH=x64
call !vsvarbat! %PLATFORM_ARCH%
if ERRORLEVEL 1 (
    echo call vsvarbat failed!
    goto final
)
set SLN_FILE="%CD%\wstd.sln"
MSBuild %SLN_FILE% /nologo /v:m /t:%TARGET_PROJECTS% /p:Configuration="Debug" /p:Platform=%PLATFORM_ARCH% /p:PlatformToolset=%PLATFORM_TOOLSET% /p:WindowsTargetPlatformVersion=%PLATFORM_VERSION%
MSBuild %SLN_FILE% /nologo /v:m /t:%TARGET_PROJECTS% /p:Configuration="Release" /p:Platform=%PLATFORM_ARCH% /p:PlatformToolset=%PLATFORM_TOOLSET% /p:WindowsTargetPlatformVersion=%PLATFORM_VERSION%
MSBuild %SLN_FILE% /nologo /v:m /t:%TARGET_PROJECTS% /p:Configuration="ReleaseMT" /p:Platform=%PLATFORM_ARCH% /p:PlatformToolset=%PLATFORM_TOOLSET% /p:WindowsTargetPlatformVersion=%PLATFORM_VERSION%

:final
pause

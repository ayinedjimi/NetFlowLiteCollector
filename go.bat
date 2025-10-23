@echo off
echo Compilation de NetFlowLiteCollector...
cl.exe /EHsc /W4 /std:c++17 /Fe:NetFlowLiteCollector.exe NetFlowLiteCollector.cpp /link ws2_32.lib comctl32.lib user32.lib gdi32.lib
if %ERRORLEVEL% EQU 0 (
    echo Compilation reussie!
    echo Executable: NetFlowLiteCollector.exe
) else (
    echo Erreur de compilation.
)
pause

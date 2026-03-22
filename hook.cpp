#include <windows.h>
#include <winspool.h>

#pragma comment(lib, "gdi32.lib")

#define MAX_TRACKED 64
#define MAX_PATH_LEN 512

//---------------------------------------------
// GLOBALS
//---------------------------------------------

typedef struct
{
    DWORD threadId;
    WCHAR path[MAX_PATH_LEN];
} FILE_TRACK;

FILE_TRACK g_tracks[MAX_TRACKED];
int g_index = 0;

CRITICAL_SECTION g_lock;

//---------------------------------------------
// ORIGINAL FUNCTION POINTERS
//---------------------------------------------

typedef HANDLE(WINAPI* PFN_CreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE);

typedef int (WINAPI* PFN_StartDocW)(
    HDC, const DOCINFOW*);

PFN_CreateFileW Real_CreateFileW = NULL;
PFN_StartDocW   Real_StartDocW   = NULL;

//---------------------------------------------
// LOG FUNCTION (NO STD)
//---------------------------------------------

void Log(LPCWSTR msg)
{
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

//---------------------------------------------
// SAFE STRING COPY (NO CRT DEPENDENCY)
//---------------------------------------------

void SafeCopy(WCHAR* dst, LPCWSTR src)
{
    int i = 0;
    if (!src) return;

    for (; i < MAX_PATH_LEN - 1 && src[i]; i++)
        dst[i] = src[i];

    dst[i] = 0;
}

//---------------------------------------------
// SAFE CONCAT
//---------------------------------------------

void SafeCat(WCHAR* dst, LPCWSTR src)
{
    int len = 0;
    while (dst[len] && len < MAX_PATH_LEN) len++;

    int i = 0;
    while (src && src[i] && (len + i) < MAX_PATH_LEN - 1)
    {
        dst[len + i] = src[i];
        i++;
    }

    dst[len + i] = 0;
}

//---------------------------------------------
// HOOK: CreateFileW
//---------------------------------------------

HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    HANDLE h = Real_CreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    if (lpFileName)
    {
        DWORD tid = GetCurrentThreadId();

        EnterCriticalSection(&g_lock);

        g_tracks[g_index].threadId = tid;
        SafeCopy(g_tracks[g_index].path, lpFileName);

        g_index = (g_index + 1) % MAX_TRACKED;

        LeaveCriticalSection(&g_lock);

        WCHAR msg[600] = L"[TRACK FILE] ";
        SafeCat(msg, lpFileName);
        Log(msg);
    }

    return h;
}

//---------------------------------------------
// HOOK: StartDocW
//---------------------------------------------

int WINAPI Hook_StartDocW(HDC hdc, const DOCINFOW* doc)
{
    WCHAR msg[1024] = L"[StartDoc]";

    if (doc && doc->lpszDocName)
    {
        SafeCat(msg, L" DocName=");
        SafeCat(msg, doc->lpszDocName);
    }

    DWORD tid = GetCurrentThreadId();

    EnterCriticalSection(&g_lock);

    BOOL found = FALSE;

    for (int i = 0; i < MAX_TRACKED; i++)
    {
        if (g_tracks[i].threadId == tid)
        {
            if (g_tracks[i].path[0])
            {
                SafeCat(msg, L" | FILE=");
                SafeCat(msg, g_tracks[i].path);
                found = TRUE;
                break;
            }
        }
    }

    LeaveCriticalSection(&g_lock);

    if (!found)
    {
        SafeCat(msg, L" | FILE=UNKNOWN");
    }

    Log(msg);

    return Real_StartDocW(hdc, doc);
}

//---------------------------------------------
// SIMPLE IAT PATCH (minimal, no std)
//---------------------------------------------

void HookIAT(LPCSTR dll, LPCSTR func, void* hook, void** original)
{
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);

    for (; imp->Name; imp++)
    {
        LPCSTR modName = (LPCSTR)((BYTE*)hModule + imp->Name);

        if (lstrcmpiA(modName, dll) != 0)
            continue;

        PIMAGE_THUNK_DATA thunk =
            (PIMAGE_THUNK_DATA)((BYTE*)hModule + imp->FirstThunk);

        for (; thunk->u1.Function; thunk++)
        {
            void** funcAddr = (void**)&thunk->u1.Function;

            FARPROC real = GetProcAddress(GetModuleHandleA(dll), func);

            if ((void*)real == *funcAddr)
            {
                DWORD oldProtect;
                VirtualProtect(funcAddr, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);

                *original = *funcAddr;
                *funcAddr = hook;

                VirtualProtect(funcAddr, sizeof(void*), oldProtect, &oldProtect);
                return;
            }
        }
    }
}

//---------------------------------------------
// INIT HOOKS
//---------------------------------------------

void InstallHooks()
{
    InitializeCriticalSection(&g_lock);

    HookIAT("kernel32.dll", "CreateFileW",
        Hook_CreateFileW, (void**)&Real_CreateFileW);

    HookIAT("gdi32.dll", "StartDocW",
        Hook_StartDocW, (void**)&Real_StartDocW);

    Log(L"[HOOKS INSTALLED]");
}

//---------------------------------------------
// DLL ENTRY
//---------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD reason,
    LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        Log(L"[HOOK DLL LOADED]");
        InstallHooks();
    }

    return TRUE;
}

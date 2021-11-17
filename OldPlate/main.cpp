#include <windows.h>
#include <tlhelp32.h>

#include <memory>
#include <filesystem>

#include "checkLatestRelease.h"
#include "resource.h"
#include "defer.h"

constexpr auto BASE_DLL_NAME = L"OldPlateCore_____";

bool isInjected(DWORD pid, LPCWSTR moduleName, PBYTE* pDllBaseAddress, std::wstring* dllPath);
bool injectDll(DWORD pid, LPCWSTR path, std::wstring* error);
bool uninjectDll(DWORD pid, PBYTE pDllBaseAddress, std::wstring* error);

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}

std::wstring format(const wchar_t* fmt, ...)
{
    va_list	va;
    va_start(va, fmt);

    size_t len = vswprintf(nullptr, 0, fmt, va);
    std::wstring wcs;
    wcs.resize(len);

    wvsprintfW(wcs.data(), fmt, va);

    va_end(va);

    return wcs;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int cmdShow)
{
    std::wstring error;

    if (checkLatestRelease() == RELEASE_RESULT::NEW_RELEASE)
    {

    }

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) == FALSE)
    {
        error = format(L"오류가 발생하였습니다.\n\n오류 정보 : OpenProcessToken (%d)", GetLastError());
        MessageBoxW(NULL, error.c_str(), OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }
    defer(CloseHandle(hToken));

    LUID luid = { 0, };
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid) == FALSE)
    {
        error = format(L"오류가 발생하였습니다.\n\n오류 정보 : LookupPrivilegeValueW (%d)", GetLastError());
        MessageBoxW(NULL, error.c_str(), OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }

    TOKEN_PRIVILEGES tp = { 0, };
    tp.PrivilegeCount = 1;
    tp.Privileges->Luid = luid;
    tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), nullptr, nullptr) == FALSE)
    {
        error = format(L"오류가 발생하였습니다.\n\n오류 정보 : AdjustTokenPrivileges (%d)", GetLastError());
        MessageBoxW(NULL, error.c_str(), OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        error = format(L"오류가 발생하였습니다.\n\n오류 정보 : GetLastError (%d) = ERROR_NOT_ALL_ASSIGNED", GetLastError());
        MessageBoxW(NULL, error.c_str(), OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////

    HWND hFFXIV = FindWindowW(L"FFXIVGAME", NULL);
    if (hFFXIV == NULL)
    {
        MessageBoxW(NULL, L"파이널 판타지 14가 실행중이 아니거나, 찾을 수 없습니다.", OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }

    DWORD pid;
    if (GetWindowThreadProcessId(hFFXIV, &pid) == 0 || pid == 0)
    {
        MessageBoxW(NULL, L"파이널 판타지 14가 실행중이 아니거나, 찾을 수 없습니다.", OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc == NULL)
    {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc == NULL)
        {
            MessageBoxW(NULL, L"권한이 없습니다. 관리자 권한으로 실행시켜주세요.", OLDPLATE_PROJECT_NAME, 0);
            return 1;
        }
    }

    CloseHandle(hProc);

    HMODULE hModule = GetModuleHandleW(NULL);
    if (hModule == NULL)
    {
        MessageBoxW(NULL, L"권한이 없습니다. 관리자 권한으로 실행시켜주세요.", OLDPLATE_PROJECT_NAME, 0);
        return 1;
    }

    PBYTE pDllBaseAddress;
    std::wstring dllPath;
    if (isInjected(pid, BASE_DLL_NAME, &pDllBaseAddress, &dllPath))
    {
        if (!uninjectDll(pid, pDllBaseAddress, &error))
            MessageBoxW(NULL, error.c_str(), OLDPLATE_PROJECT_NAME, 0);
        else
        {
            MessageBoxW(NULL, L"해제되었습니다.", OLDPLATE_PROJECT_NAME, 0);

            try
            {
                //DeleteFileW(dllPath.c_str());
                std::filesystem::remove(dllPath);
            }
            catch (...)
            {
            }
        }
    }
    else
    {
        const auto ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

        std::wstringstream filename;
        filename << BASE_DLL_NAME << ts << L".dll";

        std::filesystem::path tempPath = std::filesystem::temp_directory_path();
        tempPath = tempPath.append(filename.str());

        ////////////////////////////////////////////////////////////////////////////////////////////////////

        HRSRC hResource = FindResourceW(hInstance, MAKEINTRESOURCEW(IDR_DLL_RESOURCE1), L"DLL_RESOURCE");
        HGLOBAL hLoaded = LoadResource(hInstance, hResource);

        {
            LPVOID lpLock = LockResource(hLoaded);
            defer(FreeResource(lpLock));

            DWORD dwSize = SizeofResource(hInstance, hResource);

            HANDLE hFile = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            DWORD dwByteWritten;
            WriteFile(hFile, lpLock, dwSize, &dwByteWritten, NULL);
            CloseHandle(hFile);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////

        if (!injectDll(pid, tempPath.c_str(), &error))
            MessageBoxW(NULL, error.c_str(), OLDPLATE_PROJECT_NAME, 0);
        else
            MessageBoxW(NULL, L"적용되었습니다.", OLDPLATE_PROJECT_NAME, 0);
    }

    return 0;
}

bool isInjected(DWORD pid, LPCWSTR moduleName, PBYTE* pDllBaseAddress, std::wstring* dllPath)
{
    bool res = false;

    MODULEENTRY32W snapEntry = { 0 };
    HANDLE hSnapshot;

    snapEntry.dwSize = sizeof(MODULEENTRY32W);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == NULL) return FALSE;

    if (Module32FirstW(hSnapshot, &snapEntry))
    {
        do
        {
            if (std::wstring(snapEntry.szModule).starts_with(moduleName))
            {
                *pDllBaseAddress = snapEntry.modBaseAddr;
                *dllPath = std::wstring(snapEntry.szExePath);
                res = true;
                break;
            }
        } while (Module32NextW(hSnapshot, &snapEntry));
    }
    CloseHandle(hSnapshot);

    return res;
}

bool injectDll(DWORD pid, LPCWSTR path, std::wstring* error)
{
    bool result = false;

    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE lpLoadLibrary;

    LPVOID pBuff;
    DWORD pBuffSize;

    HANDLE hProcess;
    HANDLE hThread;

    DWORD exitCode;

    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL)
    {

        return false;
    }

    lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (lpLoadLibrary == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : GetProcAddress (%d)", GetLastError());
        return false;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : OpenProcess (%d)", GetLastError());
        return false;
    }

    pBuffSize = (lstrlen(path) + 1) * sizeof(TCHAR);
    pBuff = VirtualAllocEx(hProcess, NULL, pBuffSize, MEM_COMMIT, PAGE_READWRITE);
    if (pBuff == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : VirtualAllocEx (%d)", GetLastError());
    }
    else
    {
        if (WriteProcessMemory(hProcess, pBuff, (LPVOID)path, pBuffSize, NULL) == FALSE)
        {
            *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : WriteProcessMemory (%d)", GetLastError());
        }
        else
        {
            hThread = CreateRemoteThread(hProcess, NULL, 0, lpLoadLibrary, pBuff, 0, NULL);
            if (hThread == NULL)
            {
                *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : CreateRemoteThread (%d)", GetLastError());
            }
            else
            {
                WaitForSingleObject(hThread, INFINITE);

                if (GetExitCodeThread(hThread, &exitCode) == FALSE)
                {
                    *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : GetExitCodeThread (%d)", GetLastError());
                }
                else
                {
                    result = exitCode;
                }

                CloseHandle(hThread);
            }
        }

        VirtualFreeEx(hProcess, pBuff, 0, MEM_RELEASE);
    }

    CloseHandle(hProcess);

    return result;
}

bool uninjectDll(DWORD pid, PBYTE pDllBaseAddress, std::wstring* error)
{
    BOOL result = FALSE;

    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE lpFreeLibrary;

    HANDLE hProcess;
    HANDLE hThread;

    DWORD exitCode;

    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : GetModuleHandleW (%d)", GetLastError());
        return false;
    }

    lpFreeLibrary = (LPTHREAD_START_ROUTINE)(GetProcAddress(hKernel32, "FreeLibrary"));
    if (lpFreeLibrary == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : GetProcAddress (%d)", GetLastError());
        return false;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : OpenProcess (%d)", GetLastError());
        return false;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, lpFreeLibrary, (PVOID)pDllBaseAddress, 0, NULL);
    if (hThread == NULL)
    {
        *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : CreateRemoteThread (%d)", GetLastError());
        return false;
    }
    else
    {
        WaitForSingleObject(hThread, INFINITE);

        if (GetExitCodeThread(hThread, &exitCode) == FALSE)
        {
            *error = format(L"오류가 발생하였습니다.\n\n오류 정보 : GetExitCodeThread (%d)", GetLastError());
        }
        else
        {
            result = exitCode;
        }

        CloseHandle(hThread);
    }

    CloseHandle(hProcess);

    return result;
}

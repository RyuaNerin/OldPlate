#include <minhook.h>
#include <array>
#include <cstdint>

#include "memory_signature.h"
#include "debug_log.h"
#include "utils.h"

/*
ffxiv_dx11.exe+EF1CE0 - 48 8B C4              - mov rax,rsp
ffxiv_dx11.exe+EF1CE3 - 41 56                 - push r14
ffxiv_dx11.exe+EF1CE5 - 48 81 EC F0000000     - sub rsp,000000F0 { 240 }
ffxiv_dx11.exe+EF1CEC - 48 89 58 F0           - mov [rax-10],rbx
ffxiv_dx11.exe+EF1CF0 - 4C 8B F1              - mov r14,rcx
ffxiv_dx11.exe+EF1CF3 - 48 89 78 D8           - mov [rax-28],rdi
ffxiv_dx11.exe+EF1CF7 - 4C 89 60 D0           - mov [rax-30],r12
ffxiv_dx11.exe+EF1CFB - 4C 89 68 C8           - mov [rax-38],r13
ffxiv_dx11.exe+EF1CFF - 4C 8B 6A 28           - mov r13,[rdx+28]
ffxiv_dx11.exe+EF1D03 - 4C 89 78 C0           - mov [rax-40],r15
ffxiv_dx11.exe+EF1D07 - 49 8B D5              - mov rdx,r13
ffxiv_dx11.exe+EF1D0A - 0F29 70 A8            - movaps [rax-58],xmm6
ffxiv_dx11.exe+EF1D0E - 0F29 78 98            - movaps [rax-68],xmm7
ffxiv_dx11.exe+EF1D12 - 49 8B 40 20           - mov rax,[r8+20]
ffxiv_dx11.exe+EF1D16 - 48 89 44 24 60        - mov [rsp+60],rax
ffxiv_dx11.exe+EF1D1B - 4C 89 6C 24 70        - mov [rsp+70],r13
ffxiv_dx11.exe+EF1D20 - E8 8B0E0000           - call ffxiv_dx11.exe+EF2BB0
ffxiv_dx11.exe+EF1D25 - 49 8B 45 20           - mov rax,[r13+20]
*/

typedef void         (*nameplate_delegate)(const void* arg1, uint32_t*** arg2, const void* arg3);
const memory_signature nameplate_sig("488BC4 4156 4881EC???????? 4889??F0 4C???? 4889??D8 4C89??D0 4C89??C8 4C8B??28 4C89??C0");
void*                  nameplate_ptr = nullptr;
nameplate_delegate     nameplate_orig;

void nameplate_new(const void* arg1, uint32_t*** arg2, const void* arg3)
{
    // arg2 + 40
    //         + 32
    //            + 12 = 1 (uint32_t)
    arg2[5][4][3] = 1;
    
    nameplate_orig(arg1, arg2, arg3);
}

bool g_hooked = false;
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    OutputDebugStringW(L"ATTACHED");

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        debug_log(L"DllMain : DLL_PROCESS_ATTACH /// hModule: %x / lpReserved: %x", hModule, lpReserved);

        nameplate_ptr = nameplate_sig.scan();
        debug_log(L"nameplate_ptr : %x", nameplate_ptr);
        if (nameplate_ptr == nullptr)
        {
            debug_log_wcs(L"scan failed");
            return FALSE;
        }

        {
            auto mh = MH_Initialize();
            debug_log(L"MH_Initialize : %d", mh);
            if (mh == MH_OK)
            {
                g_hooked = true;

                MH_CreateHook(nameplate_ptr, &nameplate_new, (LPVOID*)&nameplate_orig);

                MH_EnableHook(nameplate_ptr);
            }
        }

        debug_log_wcs(L"attached");
        break;

    case DLL_PROCESS_DETACH:
        debug_log(L"DllMain : DLL_PROCESS_DETACH /// hModule: %x / lpReserved: %x", hModule, lpReserved);

        if (g_hooked)
        {
            MH_DisableHook(nameplate_ptr);

            MH_RemoveHook(nameplate_ptr);

            MH_Uninitialize();
        }

        debug_log_wcs(L"detached");
        break;

    default:
        debug_log(L"DllMain : %d /// hModule: %x / lpReserved: %x", ul_reason_for_call, hModule, lpReserved);
        break;
    }

    return TRUE;
}

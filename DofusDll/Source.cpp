#include <iostream>
#include <string>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>

#include <algorithm>
#include <cctype>
#include <format>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#include <tlhelp32.h>
#include <detours/detours.h>

#include "HookEngine.h"

using sendFnc = int (WSAAPI*)(SOCKET, const char*, int, int);
using recvFnc = int (WSAAPI*)(SOCKET, char*, int, int);

template <typename ReturnType, typename FunctionType>
ReturnType PassthroughHook(void* caller, SOCKET socket, char* buffer, int length, int flags)
{
    auto original{ (FunctionType)HookEngine::GetOriginalAddressFromHook(caller) };
    ReturnType result{};
    if (original != nullptr) {
        result = original(socket, buffer, length, flags);
    }

    return result;
}
int WSAAPI sendHook(SOCKET socket, const char* buffer, int length, int flags)
{
    std::cout << "sendHook " << length << std::endl;
    return PassthroughHook<int, sendFnc>(sendHook, socket, const_cast<char*>(buffer), length, flags);
}

int WSAAPI recvHook(SOCKET socket, char* buffer, int length, int flags)
{
    if(length != 65536)
		std::cout << "recvHook " << length << std::endl;
    return PassthroughHook<int, recvFnc>(recvHook, socket, buffer, length, flags);
}

__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID reserved)
{
    static HookEngine hookEngine{};

    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        if (AllocConsole()) {
            freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
            freopen_s((FILE**)stdout, "CONOUT$", "w", stderr);
            SetConsoleTitle(L"Console");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cerr << "DLL Loaded" << std::endl;
        }

        (void)hookEngine.Hook("Ws2_32.dll", "send", sendHook);
        (void)hookEngine.Hook("Ws2_32.dll", "recv", recvHook);
    }

    if (dwReason == DLL_PROCESS_DETACH) {
        (void)hookEngine.Unhook(std::string_view("Ws2_32.dll"), std::string_view("send"));
        (void)hookEngine.Unhook(std::string_view("Ws2_32.dll"), std::string_view("recv"));
    }

    return TRUE;
}
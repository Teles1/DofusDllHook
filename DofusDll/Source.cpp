#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <algorithm>
#include <cctype>
#include <format>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include <tlhelp32.h>
#include <detours/detours.h>

#include "HookEngine.h"

#pragma comment(lib, "Ws2_32.lib")

using sendFnc = int (WSAAPI*)(SOCKET, const char*, int, int);
using WSArecvFnc = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using recvFnc = int (WSAAPI*)(SOCKET, char*, int, int);

static std::atomic<bool> keepRunning{ true };
static SOCKET forwardingSocket = INVALID_SOCKET;
static std::mutex socketMutex;

sendFnc originalSend = nullptr;
recvFnc originalRecv = nullptr;

void ForwardData(const char* data, int length, char prefix) {
    std::lock_guard<std::mutex> lock(socketMutex);
    if (forwardingSocket == INVALID_SOCKET) {
        return;
    }

    std::vector<char> prefixedData(length + 1);
    prefixedData[0] = prefix;
    memcpy(prefixedData.data() + 1, data, length);

    if (originalSend != nullptr) {
        int result = originalSend(forwardingSocket, prefixedData.data(), static_cast<int>(prefixedData.size()), 0);
        if (result == SOCKET_ERROR) {
            closesocket(forwardingSocket);
            forwardingSocket = INVALID_SOCKET;
        }
    }
}

template <typename ReturnType, typename FunctionType>
ReturnType PassthroughHook(void* caller, SOCKET socket, char* buffer, int length, int flags) {
    auto original{ (FunctionType)HookEngine::GetOriginalAddressFromHook(caller) };
    ReturnType result{};
    if (original != nullptr) {
        result = original(socket, buffer, length, flags);
    }

    return result;
}

int WSAAPI sendHook(SOCKET socket, const char* buffer, int length, int flags) {
    std::cout << "sendHook " << length << "\n";
    ForwardData(buffer, length, 0x01);
    return originalSend(socket, const_cast<char*>(buffer), length, flags);
}
int WSAAPI recvHook(SOCKET socket, char* buffer, int length, int flags)
{
    std::cout << "recvHook " << length << "\n";
    ForwardData(buffer, length, 0x00);
    return originalRecv(socket, buffer, length, flags);
}
void SocketThread(const std::string& address, int port) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    while (keepRunning) {
        {
            std::lock_guard<std::mutex> lock(socketMutex);
            if (forwardingSocket != INVALID_SOCKET) {
                closesocket(forwardingSocket);
                forwardingSocket = INVALID_SOCKET;
            }

            forwardingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (forwardingSocket == INVALID_SOCKET) {
                std::cerr << "Error at socket(): " << WSAGetLastError() << std::endl;
                continue;
            }

            sockaddr_in clientService;
            clientService.sin_family = AF_INET;
            inet_pton(AF_INET, address.c_str(), &clientService.sin_addr);
            clientService.sin_port = htons(port);

            if (connect(forwardingSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
                std::cerr << "Failed to connect: " << WSAGetLastError() << std::endl;
                closesocket(forwardingSocket);
                forwardingSocket = INVALID_SOCKET;
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            std::cout << "Connected to forwarding server" << std::endl;
        }

        while (keepRunning) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    WSACleanup();
}

__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID reserved) {
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

        if(hookEngine.Hook("Ws2_32.dll", "send", sendHook))
            originalSend = static_cast<sendFnc>(HookEngine::GetOriginalAddressFromHook(sendHook));
        if(hookEngine.Hook("Ws2_32.dll", "recv", recvHook))
            originalRecv = static_cast<recvFnc>(HookEngine::GetOriginalAddressFromHook(recvHook));

        std::thread(SocketThread, "127.0.0.1", 12345).detach();  // Replace with your forwarding server address and port
    }

    if (dwReason == DLL_PROCESS_DETACH) {
        keepRunning = false;
        std::this_thread::sleep_for(std::chrono::seconds(1));  // Give some time for the socket thread to clean up

        (void)hookEngine.Unhook(std::string_view("Ws2_32.dll"), std::string_view("send"));
        (void)hookEngine.Unhook(std::string_view("Ws2_32.dll"), std::string_view("recv"));
    }

    return TRUE;
}

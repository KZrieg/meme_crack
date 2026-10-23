// MemeSense local check server.
//
// This replaces the earlier Python prototype. The socket behaviour is
// identical: accept a probe, answer with one fixed 28-byte reply, then drain
// the connection until the peer closes or the 15 second deadline expires.
//
// Differences from the Python version, all requested:
//   * no log file, console only
//   * a console is created explicitly, because the artifact is a DLL and a
//     DLL injected into a GUI process has no console of its own
//   * the two netsh steps that the Python version expected an operator to run
//     by hand are executed here, hidden, and their exit codes are reported
//   * a handshake event is set once the listener is up, so a loader can wait
//     for it instead of polling the port. The loader owns the event: it creates
//     and resets it before mapping this DLL, and this module only opens it.
//
// Build target: DLL only, entered through DllMain (server_src.vcxproj).
//
// Protocol: one request in, one reply out. The reply is
//   1C 00 00 0B followed by 24 zero bytes (28 bytes total).
// The reply is a fixed constant on purpose: the payload compares it byte for
// byte, so it must never be varied or padded.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#pragma comment(lib, "Ws2_32.lib")

namespace {

constexpr unsigned short kPort = 7531;
constexpr int kBacklog = 16;
constexpr int kRecvSize = 4096;
constexpr int kIoTimeoutMs = 15000;

// 1C 00 00 0B plus 24 zero bytes.
constexpr unsigned char kZeroReply[28] = {
    0x1C, 0x00, 0x00, 0x0B,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// Manual-reset events. A waiter opens them by name before the server starts;
// the server sets them, it never waits on them.
constexpr wchar_t kReadyEventName[]     = L"Local\\MemeSense_ServerReady";
constexpr wchar_t kHandshakeEventName[] = L"Local\\MemeSense_Handshake";

HANDLE g_readyEvent = nullptr;
HANDLE g_handshakeEvent = nullptr;
std::atomic<bool> g_handshakeSent{ false };
std::atomic<bool> g_stopRequested{ false };

void Log(const wchar_t* fmt, ...) {
    wchar_t buf[1024]{};
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    std::wstring line;
    line.reserve(1100);
    wchar_t stamp[32]{};
    _snwprintf_s(stamp, _countof(stamp), _TRUNCATE,
                 L"[%02u:%02u:%02u] ", st.wHour, st.wMinute, st.wSecond);
    line.append(stamp);
    line.append(buf);
    line.append(L"\n");

    HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (out && out != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ::WriteConsoleW(out, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
    }
}

// Run one command line with no window and no inherited console noise.
// Returns the process exit code, or -1 when the process could not be created.
DWORD RunHidden(const wchar_t* commandLine) {
    std::wstring mutableLine(commandLine);   // CreateProcessW may write to it

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(nullptr, mutableLine.data(), nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return static_cast<DWORD>(-1);
    }

    ::WaitForSingleObject(pi.hProcess, 30000);
    DWORD exitCode = static_cast<DWORD>(-1);
    ::GetExitCodeProcess(pi.hProcess, &exitCode);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return exitCode;
}

// Remove the firewall rule and add the loopback alias. Both steps are
// best-effort: a machine where the rule does not exist returns non-zero from
// the delete, which is expected and must not stop the server from listening.
void PrepareNetwork() {
    Log(L"netsh: deleting firewall rule \"msblock\"");
    const DWORD del = RunHidden(
        L"netsh.exe advfirewall firewall delete rule name=\"msblock\"");
    Log(L"netsh: delete rule -> %lu %s", del,
        (del == 0) ? L"(removed)" : L"(nothing to remove, continuing)");

    Log(L"netsh: adding 15.197.215.230 to \"Loopback Pseudo-Interface 1\"");
    const DWORD add = RunHidden(
        L"netsh.exe interface ipv4 add address \"Loopback Pseudo-Interface 1\" "
        L"15.197.215.230 255.255.255.255");
    Log(L"netsh: add address -> %lu %s", add,
        (add == 0) ? L"(ok)" : L"(already present or access denied)");
}

std::string PeerName(const sockaddr_in& addr) {
    char ip[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET, const_cast<in_addr*>(&addr.sin_addr), ip, sizeof(ip));
    char buf[64]{};
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s:%u", ip, ::ntohs(addr.sin_port));
    return buf;
}

// Readiness is signalled once the socket is listening. The loader waits on this
// to know the service was mapped and initialized, not that a probe arrived.
void SignalHandshake() {
    if (g_handshakeSent.exchange(true)) return;
    if (g_handshakeEvent) ::SetEvent(g_handshakeEvent);
    Log(L"handshake signalled (listener is up)");
}

void HandleClient(SOCKET client, sockaddr_in peer) {
    const std::string name = PeerName(peer);

    // recv timeout, matching the Python connection deadline.
    DWORD timeout = kIoTimeoutMs;
    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    char request[kRecvSize]{};
    const int received = ::recv(client, request, kRecvSize, 0);
    if (received <= 0) {
        char msg[160]{};
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "%s closed without data", name.c_str());
        wchar_t wide[160]{};
        ::MultiByteToWideChar(CP_UTF8, 0, msg, -1, wide, 160);
        Log(L"%ls", wide);
        ::closesocket(client);
        return;
    }

    const int sent = ::send(client, reinterpret_cast<const char*>(kZeroReply),
                            static_cast<int>(sizeof(kZeroReply)), 0);
    {
        char msg[192]{};
        _snprintf_s(msg, sizeof(msg), _TRUNCATE, "%s check ok (in %dB, out %dB)",
                    name.c_str(), received, sent);
        wchar_t wide[192]{};
        ::MultiByteToWideChar(CP_UTF8, 0, msg, -1, wide, 192);
        Log(L"%ls", wide);
    }

    (void)sent;

    // Drain until the peer closes or the receive deadline expires, so the
    // client never sees a reset while it is still reading.
    for (;;) {
        char drain[kRecvSize];
        const int n = ::recv(client, drain, kRecvSize, 0);
        if (n <= 0) break;
    }

    ::closesocket(client);
}

// Create the listener and serve until g_stopRequested becomes true.
// Returns false only when the socket can never work.
bool Serve() {
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        Log(L"server: socket() failed, WSA error %d", ::WSAGetLastError());
        return false;
    }

    BOOL exclusive = FALSE;
    ::setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                 reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = ::htons(kPort);

    if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        Log(L"server: cannot bind port %u, WSA error %d (already running?)",
            kPort, ::WSAGetLastError());
        ::closesocket(listener);
        return false;
    }

    if (::listen(listener, kBacklog) == SOCKET_ERROR) {
        Log(L"server: listen() failed, WSA error %d", ::WSAGetLastError());
        ::closesocket(listener);
        return false;
    }

    Log(L"MemeSense local check server ready on 0.0.0.0:%u", kPort);
    if (g_readyEvent) ::SetEvent(g_readyEvent);
    SignalHandshake();

    while (!g_stopRequested.load()) {
        sockaddr_in peer{};
        int peerLen = sizeof(peer);
        SOCKET client = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerLen);
        if (client == INVALID_SOCKET) {
            if (g_stopRequested.load()) break;
            ::Sleep(20);
            continue;
        }
        std::thread(HandleClient, client, peer).detach();
    }

    ::closesocket(listener);
    return true;
}

// QuickEdit turns any click in the console into a selection that blocks the
// process while it holds the screen buffer. A server must never be suspended by
// an accidental click, so the mode is cleared on both input and output handles.
void DisableQuickEdit() {
    for (DWORD which : { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE }) {
        HANDLE h = ::GetStdHandle(which);
        if (!h || h == INVALID_HANDLE_VALUE) continue;

        DWORD mode = 0;
        if (!::GetConsoleMode(h, &mode)) continue;

        mode &= ~ENABLE_QUICK_EDIT_MODE;
        mode |= ENABLE_EXTENDED_FLAGS;   // required for the change to take effect
        mode &= ~ENABLE_INSERT_MODE;
        ::SetConsoleMode(h, mode);
    }
}

// Attach to the calling console if there is one, otherwise allocate one.
void EnsureConsole() {
    if (::GetConsoleWindow() != nullptr) {
        ::SetConsoleOutputCP(CP_UTF8);
        DisableQuickEdit();
        return;
    }
    if (::AllocConsole()) {
        ::SetConsoleOutputCP(CP_UTF8);
        ::SetConsoleTitleW(L"MemeSense Check Server");
        DisableQuickEdit();
    }
}

void StartServerThread() {
    std::thread([] {
        EnsureConsole();
        Log(L"MemeSense check server starting (pid %lu)", ::GetCurrentProcessId());

        WSADATA wsa{};
        const int startup = ::WSAStartup(MAKEWORD(2, 2), &wsa);
        if (startup != 0) {
            Log(L"server: WSAStartup failed with %d", startup);
            return;
        }

        // The loader creates and resets both events before mapping this DLL, so
        // a signalled handle here always means this run. Open first and only
        // create as a fallback, when the DLL is loaded by something else.
        g_readyEvent = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, kReadyEventName);
        if (!g_readyEvent) {
            g_readyEvent = ::CreateEventW(nullptr, TRUE, FALSE, kReadyEventName);
        }

        g_handshakeEvent = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, kHandshakeEventName);
        if (!g_handshakeEvent) {
            g_handshakeEvent = ::CreateEventW(nullptr, TRUE, FALSE, kHandshakeEventName);
        }

        PrepareNetwork();

        if (!Serve()) {
            Log(L"server: stopped after startup failure");
        }

        ::WSACleanup();
    }).detach();
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(module);
        StartServerThread();
        break;

    case DLL_PROCESS_DETACH:
        g_stopRequested.store(true);
        break;

    default:
        break;
    }
    return TRUE;
}

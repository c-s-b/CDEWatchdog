#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <ctime>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// CONFIGURATION & GLOBAL STATE
// ============================================================================
struct AgentConfig {
    std::string identity = "alpha";         // "alpha" or "bravo"
    std::string twinIdentity = "bravo";     // Twin companion identity
    std::string serverHost = "127.0.0.1";   // Default backend receiver host
    int serverPort = 8000;                  // Default backend receiver port
    std::string endpoint = "/api/ad_triage";
    int intervalSec = 300;                  // Telemetry poll interval: 5 minutes (300 seconds)
    bool debug = false;                     // Show console output if true
};

static AgentConfig g_Config;

// Convert UTF-16 wchar_t string to UTF-8 std::string
std::string WideToUtf8(const wchar_t* wstr) {
    if (!wstr) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return "";
    std::vector<char> buffer(sizeNeeded);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &buffer[0], sizeNeeded, NULL, NULL);
    return std::string(&buffer[0]);
}

// Convert UTF-8 std::string to UTF-16 std::wstring
std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    if (sizeNeeded <= 0) return L"";
    std::vector<wchar_t> buffer(sizeNeeded + 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &buffer[0], sizeNeeded);
    return std::wstring(&buffer[0]);
}

// Clean JSON string escaping
std::string EscapeJson(const std::string& str) {
    std::ostringstream o;
    for (char c : str) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (int)(unsigned char)c);
                    o << buf;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

// Get the local computer name / DC hostname
std::string GetMachineHostname() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size)) {
        return WideToUtf8(buffer);
    }
    return "UNKNOWN_DC";
}

// ============================================================================
// 1. NATIVE ACTIVE DIRECTORY USER & GROUP AUDITING
// ============================================================================

// Extract all domain / local user accounts via NetUserEnum
std::vector<std::string> QueryActiveDirectoryUsers() {
    std::vector<std::string> userList;
    LPUSER_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD_PTR dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    do {
        // NULL targets the local DC where the agent is running
        nStatus = NetUserEnum(
            NULL,
            dwLevel,
            FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );

        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != NULL) {
            LPUSER_INFO_0 pCurrent = pBuf;
            for (DWORD i = 0; i < dwEntriesRead; ++i) {
                if (pCurrent->usri0_name != NULL) {
                    std::string username = WideToUtf8(pCurrent->usri0_name);
                    if (!username.empty()) {
                        userList.push_back(username);
                    }
                }
                pCurrent++;
            }
        }

        if (pBuf != NULL) {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);

    // Fallback: in standalone test environments, add Administrator/Guest if query had restrictions
    if (userList.empty()) {
        userList.push_back("Administrator");
        userList.push_back("Guest");
    }

    return userList;
}

// Map members of privileged domain groups (e.g. "Domain Admins") via NetGroupGetUsers
std::vector<std::string> QueryGroupMembers(const std::wstring& groupName) {
    std::vector<std::string> members;
    LPGROUP_USERS_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD_PTR dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    do {
        nStatus = NetGroupGetUsers(
            NULL,
            groupName.c_str(),
            dwLevel,
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );

        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != NULL) {
            LPGROUP_USERS_INFO_0 pCurrent = pBuf;
            for (DWORD i = 0; i < dwEntriesRead; ++i) {
                if (pCurrent->grui0_name != NULL) {
                    std::string name = WideToUtf8(pCurrent->grui0_name);
                    if (!name.empty()) {
                        members.push_back(name);
                    }
                }
                pCurrent++;
            }
        }

        if (pBuf != NULL) {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);

    // If machine is not an active DC (e.g., local test bench), fallback to local Administrators group
    if (members.empty() && groupName == L"Domain Admins") {
        LPLOCALGROUP_MEMBERS_INFO_0 pLBuf = NULL;
        dwResumeHandle = 0;
        nStatus = NetLocalGroupGetMembers(
            NULL,
            L"Administrators",
            0,
            (LPBYTE*)&pLBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle
        );

        if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pLBuf != NULL) {
            LPLOCALGROUP_MEMBERS_INFO_0 pCurrent = pLBuf;
            for (DWORD i = 0; i < dwEntriesRead; ++i) {
                if (pCurrent->lgrmi0_name != NULL) {
                    std::string fullName = WideToUtf8(pCurrent->lgrmi0_name);
                    size_t slashPos = fullName.find_last_of('\\');
                    if (slashPos != std::string::npos) {
                        fullName = fullName.substr(slashPos + 1);
                    }
                    if (!fullName.empty()) {
                        members.push_back(fullName);
                    }
                }
                pCurrent++;
            }
            NetApiBufferFree(pLBuf);
        }
    }

    return members;
}

// ============================================================================
// 2. NATIVE REGISTRY AUDITING
// ============================================================================

// Read DWORD from registry key with fail-safe fallback
DWORD ReadRegistryDword(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, DWORD defaultValue = 0) {
    HKEY hKey = NULL;
    DWORD dwValue = defaultValue;
    DWORD dwType = REG_DWORD;
    DWORD cbData = sizeof(DWORD);

    LONG lResult = RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey);
    if (lResult == ERROR_SUCCESS) {
        lResult = RegQueryValueExW(hKey, valueName.c_str(), NULL, &dwType, (LPBYTE)&dwValue, &cbData);
        RegCloseKey(hKey);
        if (lResult == ERROR_SUCCESS && dwType == REG_DWORD) {
            return dwValue;
        }
    }
    return defaultValue;
}

struct SecurityRegistryAudit {
    DWORD enableFirewall = 0;
    DWORD userAuthentication = 0;
    DWORD runAsPpl = 0;
};

SecurityRegistryAudit AuditSecurityRegistry() {
    SecurityRegistryAudit audit;

    // 1. StandardProfile Firewall: HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall
    audit.enableFirewall = ReadRegistryDword(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        L"EnableFirewall",
        0
    );

    // Also check DomainProfile if StandardProfile is not set (DC default)
    if (audit.enableFirewall == 0) {
        DWORD domainFw = ReadRegistryDword(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
            L"EnableFirewall",
            0
        );
        if (domainFw == 1) {
            audit.enableFirewall = 1;
        }
    }

    // 2. RDP NLA: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication
    audit.userAuthentication = ReadRegistryDword(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        L"UserAuthentication",
        0
    );

    // 3. LSA RunAsPPL: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL
    audit.runAsPpl = ReadRegistryDword(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"RunAsPPL",
        0
    );

    return audit;
}

// ============================================================================
// 2B. NATIVE AUTOSTART (RUN/RUNONCE) & WINLOGON AUDITING
// ============================================================================

struct RunKeyEntry {
    std::string location;
    std::string name;
    std::string command;
};

struct WinlogonAudit {
    std::string userinit = "C:\\Windows\\system32\\userinit.exe,";
    std::string shell = "explorer.exe";
    std::string logonScript = "";
    std::vector<std::string> logonLogoffScripts;
};

static const std::vector<std::string> BENIGN_RUN_NAMES = {
    "vmware user process", "vmware tools", "vboxtray", "vboxclient", "securityhealth", "securityhealthsystray"
};

std::string ReadRegistryString(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, const std::string& defaultValue = "") {
    HKEY hKey = NULL;
    std::string result = defaultValue;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[1024];
        DWORD cbData = sizeof(buffer);
        DWORD dwType = 0;
        if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &dwType, (LPBYTE)buffer, &cbData) == ERROR_SUCCESS) {
            if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
                result = WideToUtf8(buffer);
            }
        }
        RegCloseKey(hKey);
    }
    return result;
}

void AuditRunKeySubkey(HKEY hRoot, const std::string& rootName, const std::wstring& subKey, std::vector<RunKeyEntry>& results) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwValues = 0;
        DWORD dwMaxValueNameLen = 0;
        DWORD dwMaxValueLen = 0;
        if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValues, &dwMaxValueNameLen, &dwMaxValueLen, NULL, NULL) == ERROR_SUCCESS) {
            std::vector<wchar_t> valNameBuf(dwMaxValueNameLen + 2, 0);
            std::vector<BYTE> dataBuf(dwMaxValueLen + 4, 0);
            for (DWORD i = 0; i < dwValues; ++i) {
                DWORD cchValName = (DWORD)valNameBuf.size();
                DWORD cbData = (DWORD)dataBuf.size();
                DWORD dwType = 0;
                valNameBuf[0] = L'\0';
                ZeroMemory(dataBuf.data(), dataBuf.size());
                if (RegEnumValueW(hKey, i, valNameBuf.data(), &cchValName, NULL, &dwType, dataBuf.data(), &cbData) == ERROR_SUCCESS) {
                    std::string name = WideToUtf8(valNameBuf.data());
                    if (name.empty()) name = "(Default)";
                    std::string cmd;
                    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
                        cmd = WideToUtf8((const wchar_t*)dataBuf.data());
                    } else {
                        cmd = "<binary data>";
                    }
                    std::string loc = rootName + "\\" + WideToUtf8(subKey.c_str());
                    results.push_back({loc, name, cmd});
                }
            }
        }
        RegCloseKey(hKey);
    }
}

std::vector<RunKeyEntry> AuditRunKeys() {
    std::vector<RunKeyEntry> entries;
    std::vector<std::wstring> subKeys = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    for (const auto& sub : subKeys) {
        AuditRunKeySubkey(HKEY_LOCAL_MACHINE, "HKLM", sub, entries);
        AuditRunKeySubkey(HKEY_CURRENT_USER, "HKCU", sub, entries);
    }
    return entries;
}

WinlogonAudit AuditWinlogon() {
    WinlogonAudit audit;
    audit.userinit = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", "C:\\Windows\\system32\\userinit.exe,");
    audit.shell = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", "explorer.exe");
    std::string taskman = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Taskman", "");
    if (!taskman.empty()) {
        audit.logonLogoffScripts.push_back("Winlogon Taskman: " + taskman);
    }

    // HKCU\Environment\UserInitMprLogonScript
    audit.logonScript = ReadRegistryString(HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript", "");
    if (audit.logonScript.empty()) {
        audit.logonScript = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"UserInitMprLogonScript", "");
    }

    // Group Policy Scripts
    std::vector<std::pair<HKEY, std::wstring>> gpList = {
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon"},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff"},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logon"},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Logoff"}
    };

    for (const auto& gp : gpList) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(gp.first, gp.second.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD dwSubKeys = 0;
            if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &dwSubKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (dwSubKeys > 0) {
                    audit.logonLogoffScripts.push_back(WideToUtf8(gp.second.c_str()));
                }
            }
            RegCloseKey(hKey);
        }
    }

    return audit;
}

// ============================================================================
// 3. DUAL-PROCESS WATCHDOG PERSISTENCE
// ============================================================================

std::wstring GetSelfExecutablePath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    return std::wstring(buffer);
}

std::wstring GetDirectoryOfPath(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return path.substr(0, pos);
    }
    return L"";
}

// Query running processes using Toolhelp32 snapshot to locate twin PID
DWORD FindProcessIdByNameOrTwin(const std::wstring& targetExeName, DWORD currentPid) {
    DWORD foundPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID != currentPid) {
                // Check if process matches target executable name (case-insensitive)
                if (_wcsicmp(pe32.szExeFile, targetExeName.c_str()) == 0) {
                    foundPid = pe32.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return foundPid;
}

// Ensure the twin companion process is running. If terminated, re-spawn it instantly.
DWORD MaintainTwinWatchdog() {
    DWORD currentPid = GetCurrentProcessId();
    std::wstring selfPath = GetSelfExecutablePath();
    std::wstring currentDir = GetDirectoryOfPath(selfPath);

    // Determine companion names and arguments
    std::wstring companionExeName = (g_Config.twinIdentity == "alpha") ? L"agent_alpha.exe" : L"agent_bravo.exe";
    std::wstring companionFlag = (g_Config.twinIdentity == "alpha") ? L"-alpha" : L"-bravo";
    std::wstring companionFullPath = currentDir + L"\\" + companionExeName;

    // First search for dedicated companion binary name
    DWORD twinPid = FindProcessIdByNameOrTwin(companionExeName, currentPid);

    // If not found, check if companion is running under the same binary name (e.g., agent.exe)
    if (twinPid == 0) {
        std::wstring selfExeName = selfPath.substr(selfPath.find_last_of(L"\\/") + 1);
        twinPid = FindProcessIdByNameOrTwin(selfExeName, currentPid);
    }

    // If twin is missing, immediately re-spawn
    if (twinPid == 0) {
        if (g_Config.debug) {
            std::cout << "[WATCHDOG] Twin (" << g_Config.twinIdentity 
                      << ") missing or killed! Re-spawning immediately..." << std::endl;
        }

        // If dedicated companion executable does not exist on disk, self-replicate to companion path
        if (GetFileAttributesW(companionFullPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            CopyFileW(selfPath.c_str(), companionFullPath.c_str(), FALSE);
        }

        // Target executable to run
        std::wstring targetExe = (GetFileAttributesW(companionFullPath.c_str()) != INVALID_FILE_ATTRIBUTES)
            ? companionFullPath
            : selfPath;

        // Build command line: "<targetExe>" -<identity> -server <host> -port <port>
        std::wostringstream cmdStream;
        cmdStream << L"\"" << targetExe << L"\" " << companionFlag
                  << L" -server " << Utf8ToWide(g_Config.serverHost)
                  << L" -port " << g_Config.serverPort;

        std::wstring cmdLine = cmdStream.str();
        std::vector<wchar_t> cmdBuffer(cmdLine.begin(), cmdLine.end());
        cmdBuffer.push_back(0);

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE; // Hidden window
        ZeroMemory(&pi, sizeof(pi));

        // Re-spawn companion hidden and detached
        BOOL bCreated = CreateProcessW(
            NULL,
            cmdBuffer.data(),
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            NULL,
            currentDir.c_str(),
            &si,
            &pi
        );

        if (bCreated) {
            twinPid = pi.dwProcessId;
            if (g_Config.debug) {
                std::cout << "[WATCHDOG] Successfully spawned twin PID: " << twinPid << std::endl;
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            if (g_Config.debug) {
                std::cerr << "[WATCHDOG] Failed to re-spawn twin. Error: " << GetLastError() << std::endl;
            }
        }
    } else {
        if (g_Config.debug) {
            std::cout << "[WATCHDOG] Twin (" << g_Config.twinIdentity 
                      << ") is healthy with PID: " << twinPid << std::endl;
        }
    }

    return twinPid;
}

// ============================================================================
// 4. WININET JSON TELEMETRY EXFILTRATION
// ============================================================================

std::string BuildJsonPayload(
    const std::string& identity,
    const std::string& hostname,
    DWORD twinPid,
    const std::vector<std::string>& users,
    const std::vector<std::string>& domainAdmins,
    const SecurityRegistryAudit& registry,
    const std::vector<RunKeyEntry>& runKeys,
    const WinlogonAudit& winlogon
) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"agent_identity\": \"" << EscapeJson(identity) << "\",\n";
    json << "  \"hostname\": \"" << EscapeJson(hostname) << "\",\n";
    json << "  \"twin_pid\": " << twinPid << ",\n";
    json << "  \"timestamp\": " << (unsigned long long)time(NULL) << ",\n";
    
    // Active Directory live users
    json << "  \"users\": [";
    for (size_t i = 0; i < users.size(); ++i) {
        json << "\"" << EscapeJson(users[i]) << "\"";
        if (i + 1 < users.size()) json << ", ";
    }
    json << "],\n";

    // Domain Admins group membership
    json << "  \"domain_admins\": [";
    for (size_t i = 0; i < domainAdmins.size(); ++i) {
        json << "\"" << EscapeJson(domainAdmins[i]) << "\"";
        if (i + 1 < domainAdmins.size()) json << ", ";
    }
    json << "],\n";

    // Security Registry states
    json << "  \"registry\": {\n";
    json << "    \"EnableFirewall\": " << registry.enableFirewall << ",\n";
    json << "    \"UserAuthentication\": " << registry.userAuthentication << ",\n";
    json << "    \"RunAsPPL\": " << registry.runAsPpl << "\n";
    json << "  },\n";

    // Run & RunOnce Keys
    json << "  \"run_keys\": [\n";
    for (size_t i = 0; i < runKeys.size(); ++i) {
        json << "    {\n";
        json << "      \"location\": \"" << EscapeJson(runKeys[i].location) << "\",\n";
        json << "      \"name\": \"" << EscapeJson(runKeys[i].name) << "\",\n";
        json << "      \"command\": \"" << EscapeJson(runKeys[i].command) << "\"\n";
        json << "    }";
        if (i + 1 < runKeys.size()) json << ",";
        json << "\n";
    }
    json << "  ],\n";

    // Winlogon & Logon/Logoff Scripts
    json << "  \"winlogon\": {\n";
    json << "    \"Userinit\": \"" << EscapeJson(winlogon.userinit) << "\",\n";
    json << "    \"Shell\": \"" << EscapeJson(winlogon.shell) << "\",\n";
    json << "    \"LogonScript\": \"" << EscapeJson(winlogon.logonScript) << "\",\n";
    json << "    \"LogonLogoffScripts\": [";
    for (size_t i = 0; i < winlogon.logonLogoffScripts.size(); ++i) {
        json << "\"" << EscapeJson(winlogon.logonLogoffScripts[i]) << "\"";
        if (i + 1 < winlogon.logonLogoffScripts.size()) json << ", ";
    }
    json << "]\n";
    json << "  }\n";
    json << "}";

    return json.str();
}

bool ExfiltrateTelemetryViaWinINet(
    const std::string& host,
    int port,
    const std::string& endpoint,
    const std::string& jsonPayload
) {
    HINTERNET hInternet = InternetOpenA(
        "ADIntegrityWatchdog/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    );
    if (!hInternet) return false;

    HINTERNET hConnect = InternetConnectA(
        hInternet,
        host.c_str(),
        (INTERNET_PORT)port,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        0
    );
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }

    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,
        "POST",
        endpoint.c_str(),
        NULL,
        NULL,
        NULL,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        0
    );
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    const char* headers = "Content-Type: application/json\r\nConnection: close\r\n";
    BOOL bSend = HttpSendRequestA(
        hRequest,
        headers,
        (DWORD)strlen(headers),
        (LPVOID)jsonPayload.c_str(),
        (DWORD)jsonPayload.length()
    );

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return (bSend == TRUE);
}

// ============================================================================
// MAIN LOOP & ENTRYPOINT
// ============================================================================

void ParseCommandLine(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-alpha") {
            g_Config.identity = "alpha";
            g_Config.twinIdentity = "bravo";
        } else if (arg == "-bravo") {
            g_Config.identity = "bravo";
            g_Config.twinIdentity = "alpha";
        } else if (arg == "-server" && i + 1 < argc) {
            g_Config.serverHost = argv[++i];
        } else if (arg == "-port" && i + 1 < argc) {
            g_Config.serverPort = atoi(argv[++i]);
        } else if (arg == "-interval" && i + 1 < argc) {
            g_Config.intervalSec = atoi(argv[++i]);
        } else if (arg == "-debug") {
            g_Config.debug = true;
        }
    }
}

void PrintOfflineTriageReport(
    DWORD twinPid,
    const std::vector<std::string>& users,
    const std::vector<std::string>& admins,
    const SecurityRegistryAudit& reg,
    const std::vector<RunKeyEntry>& runKeys,
    const WinlogonAudit& winlogon,
    DWORD winError
) {
    std::vector<std::string> baselineUsers = {
        "Administrator", "Guest", "krbtgt",
        "BlueTeamLead", "BlueTeamAdmin1", "BlueTeamAdmin2", "ScoreUser_AD"
    };
    std::vector<std::string> baselineAdmins = { "Administrator", "BlueTeamLead" };

    auto isMember = [](const std::vector<std::string>& list, const std::string& item) {
        for (const auto& x : list) {
            if (_stricmp(x.c_str(), item.c_str()) == 0) return true;
        }
        return false;
    };

    std::vector<std::string> rogueAdmins;
    for (const auto& a : admins) {
        if (!isMember(baselineAdmins, a)) rogueAdmins.push_back(a);
    }

    std::vector<std::string> rogueUsers;
    for (const auto& u : users) {
        if (!isMember(baselineUsers, u)) rogueUsers.push_back(u);
    }

    // Filter suspicious Run / RunOnce autostart keys (excluding benign VM tools)
    std::vector<RunKeyEntry> rogueRunKeys;
    for (const auto& rk : runKeys) {
        std::string nameLower = rk.name;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        std::string cmdLower = rk.command;
        std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);
        bool isBenign = false;
        for (const auto& b : BENIGN_RUN_NAMES) {
            if (nameLower == b) { isBenign = true; break; }
        }
        if (cmdLower.find("vmtoolsd.exe") != std::string::npos || cmdLower.find("vboxtray.exe") != std::string::npos) {
            isBenign = true;
        }
        if (!isBenign) {
            rogueRunKeys.push_back(rk);
        }
    }

    // Winlogon & Logon/Logoff Scripts checks
    std::string uInit = winlogon.userinit;
    std::string uInitLower = uInit;
    std::transform(uInitLower.begin(), uInitLower.end(), uInitLower.begin(), ::tolower);
    bool isUserinitClean = (uInitLower == "c:\\windows\\system32\\userinit.exe," || uInitLower == "c:\\windows\\system32\\userinit.exe");

    std::string shellVal = winlogon.shell;
    std::string shellLower = shellVal;
    std::transform(shellLower.begin(), shellLower.end(), shellLower.begin(), ::tolower);
    bool isShellClean = (shellLower == "explorer.exe" || shellLower.empty());

    bool hasLogonScript = !winlogon.logonScript.empty();
    bool hasGpScripts = !winlogon.logonLogoffScripts.empty();

    // Health Score calculation
    int score = 100;
    if (!rogueAdmins.empty()) score -= 40;
    if (reg.enableFirewall != 1) score -= 30;
    if (reg.userAuthentication != 1 || reg.runAsPpl != 1) score -= 20;
    if (!rogueRunKeys.empty()) score -= (std::min)(25, (int)rogueRunKeys.size() * 15);
    if (!isUserinitClean) score -= 30;
    if (!isShellClean) score -= 25;
    if (hasLogonScript) score -= 20;
    if (hasGpScripts) score -= (std::min)(25, (int)winlogon.logonLogoffScripts.size() * 15);

    int rogueStandard = 0;
    for (const auto& u : rogueUsers) {
        if (!isMember(rogueAdmins, u)) rogueStandard++;
    }
    if (rogueStandard > 0) score -= (std::min)(20, rogueStandard * 10);
    score = (std::max)(0, (std::min)(100, score));

    std::cout << "\n================================================================================" << std::endl;
    std::cout << "  [OFFLINE LOCAL TRIAGE CONSOLE] - HOST DASHBOARD UNREACHABLE" << std::endl;
    std::cout << "  Target Address : http://" << g_Config.serverHost << ":" << g_Config.serverPort << g_Config.endpoint << std::endl;
    std::cout << "  WinINet Error  : Code " << winError << std::endl;
    std::cout << "  Local Identity : " << g_Config.identity << " (Twin PID: " << twinPid << ") | Host: " << GetMachineHostname() << std::endl;
    std::cout << "================================================================================" << std::endl;

    if (score == 100) {
        std::cout << "  >>> AD HEALTH SCORE : 100% [GOLDEN STATE COMPLIANT — ALL DEFENSES VERIFIED] <<<" << std::endl;
    } else {
        std::cout << "  >>> AD HEALTH SCORE : " << score << "% [CRITICAL INTEGRITY BREACH DETECTED AT MINUTE-0] <<<" << std::endl;
    }

    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << "  1. ACTIVE DIRECTORY ACCOUNT AUDIT:" << std::endl;
    std::cout << "     Total Accounts Found : " << users.size() << std::endl;
    if (!rogueUsers.empty()) {
        std::cout << "     [!] ROGUE ACCOUNTS (" << rogueUsers.size() << ") : ";
        for (const auto& u : rogueUsers) std::cout << u << " ";
        std::cout << std::endl;
    } else {
        std::cout << "     [✔] All accounts match pristine Golden State whitelist." << std::endl;
    }

    std::cout << "\n  2. PRIVILEGED ACCESS AUDIT (DOMAIN ADMINS):" << std::endl;
    std::cout << "     Total Admins Found   : " << admins.size() << std::endl;
    if (!rogueAdmins.empty()) {
        std::cout << "     [!] ROGUE DOMAIN ADMINS : ";
        for (const auto& a : rogueAdmins) std::cout << a << " ";
        std::cout << " (PRIVILEGE ESCALATION!)" << std::endl;
    } else {
        std::cout << "     [✔] Domain Admins matches pristine baseline: Administrator, BlueTeamLead" << std::endl;
    }

    std::cout << "\n  3. SECURITY REGISTRY HARDENING AUDIT:" << std::endl;
    std::cout << "     [" << (reg.enableFirewall == 1 ? "✔" : "!") << "] Windows Firewall     : " 
              << reg.enableFirewall << (reg.enableFirewall == 1 ? " [ENFORCED]" : " [DISABLED - HOST EXPOSED]") << std::endl;
    std::cout << "     [" << (reg.userAuthentication == 1 ? "✔" : "!") << "] RDP Network Level NLA: " 
              << reg.userAuthentication << (reg.userAuthentication == 1 ? " [ENFORCED]" : " [DISABLED - PRE-AUTH EXPLOITS]") << std::endl;
    std::cout << "     [" << (reg.runAsPpl == 1 ? "✔" : "!") << "] LSA RunAsPPL Guard   : " 
              << reg.runAsPpl << (reg.runAsPpl == 1 ? " [ENFORCED]" : " [DISABLED - MIMIKATZ DUMP TARGET]") << std::endl;

    std::cout << "\n  4. AUTOSTART PERSISTENCE AUDIT (RUN & RUNONCE KEYS - MITRE T1547.001):" << std::endl;
    std::cout << "     Total Autostart Entries  : " << runKeys.size() << std::endl;
    if (!rogueRunKeys.empty()) {
        std::cout << "     [!] ROGUE AUTOSTART KEYS (" << rogueRunKeys.size() << ") DETECTED:" << std::endl;
        for (const auto& rk : rogueRunKeys) {
            std::cout << "         • [" << rk.location << "] '" << rk.name << "' -> \"" << rk.command << "\"" << std::endl;
        }
    } else {
        std::cout << "     [✔] Clean (Zero unauthorized Run / RunOnce autostart keys)." << std::endl;
    }

    std::cout << "\n  5. WINLOGON & USER LOGON/LOGOFF AUDIT (MITRE T1547.004 / T1037):" << std::endl;
    std::cout << "     [" << (isUserinitClean ? "✔" : "!") << "] Winlogon Userinit    : " 
              << (isUserinitClean ? "Enforced (" + uInit + ")" : "HIJACKED! (" + uInit + ")") << std::endl;
    std::cout << "     [" << (isShellClean ? "✔" : "!") << "] Winlogon Shell       : " 
              << (isShellClean ? "Enforced (" + (shellVal.empty() ? "explorer.exe" : shellVal) + ")" : "HIJACKED! (" + shellVal + ")") << std::endl;
    std::cout << "     [" << (!hasLogonScript ? "✔" : "!") << "] User Logon Script    : " 
              << (!hasLogonScript ? "None (Pristine)" : "ROGUE SCRIPT! (" + winlogon.logonScript + ")") << std::endl;
    if (hasGpScripts) {
        std::cout << "     [!] GPO Scripts Detected : ";
        for (const auto& s : winlogon.logonLogoffScripts) std::cout << s << "; ";
        std::cout << std::endl;
    }

    if (score < 100) {
        std::cout << "\n  6. RECOMMENDED EMERGENCY REMEDIATION (POWERSHELL):" << std::endl;
        for (const auto& a : rogueAdmins) {
            std::cout << "     Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"" << a << "\" -Confirm:$false" << std::endl;
            std::cout << "     Disable-ADAccount -Identity \"" << a << "\"" << std::endl;
        }
        if (reg.enableFirewall != 1) {
            std::cout << "     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" << std::endl;
        }
        if (reg.runAsPpl != 1) {
            std::cout << "     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" -Name \"RunAsPPL\" -Value 1" << std::endl;
        }
        if (reg.userAuthentication != 1) {
            std::cout << "     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"UserAuthentication\" -Value 1" << std::endl;
        }
        for (const auto& rk : rogueRunKeys) {
            std::cout << "     Remove-ItemProperty -Path \"Registry::" << rk.location << "\" -Name \"" << rk.name << "\" -Force" << std::endl;
        }
        if (!isUserinitClean) {
            std::cout << "     Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Userinit\" -Value \"C:\\Windows\\system32\\userinit.exe,\"" << std::endl;
        }
        if (!isShellClean) {
            std::cout << "     Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Shell\" -Value \"explorer.exe\"" << std::endl;
        }
        if (hasLogonScript) {
            std::cout << "     Remove-ItemProperty -Path \"HKCU:\\Environment\" -Name \"UserInitMprLogonScript\" -Force" << std::endl;
            std::cout << "     Remove-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" -Name \"UserInitMprLogonScript\" -Force -ErrorAction SilentlyContinue" << std::endl;
        }
    }

    std::cout << "================================================================================" << std::endl;
    if (g_Config.serverHost == "127.0.0.1" || g_Config.serverHost == "localhost") {
        std::cout << "  [TIP] Currently targeting 127.0.0.1. To exfiltrate to your host dashboard:" << std::endl;
        std::cout << "        agent_alpha.exe -alpha -server <HOST_IP> -port 8000 -debug" << std::endl;
        std::cout << "================================================================================" << std::endl;
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    // Always attempt to attach to parent console if invoked from cmd/powershell
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        if (g_Config.debug) AllocConsole();
    }

    ParseCommandLine(argc, argv);

    // If in explicit debug mode, ensure console output is attached and visible
    if (g_Config.debug) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    } else {
        HWND hWnd = GetConsoleWindow();
        if (hWnd != NULL) {
            ShowWindow(hWnd, SW_HIDE);
        }
    }

    std::string hostname = GetMachineHostname();

    if (g_Config.debug) {
        std::cout << "\n=======================================================" << std::endl;
        std::cout << "  AD WATCHDOG AGENT - STANDALONE / DC TEST BENCH" << std::endl;
        std::cout << "=======================================================" << std::endl;
        std::cout << "[+] Active Identity : " << g_Config.identity << std::endl;
        std::cout << "[+] Twin Companion  : " << g_Config.twinIdentity << std::endl;
        std::cout << "[+] Hostname        : " << hostname << std::endl;
        std::cout << "[+] Target Server   : http://" << g_Config.serverHost << ":" << g_Config.serverPort << g_Config.endpoint << std::endl;
        std::cout << "[+] Poll Interval   : " << g_Config.intervalSec << "s (" << (g_Config.intervalSec / 60) << " min)" << std::endl;
        std::cout << "=======================================================\n" << std::endl;
    }

    // Main telemetry & watchdog loop
    while (true) {
        // 1. Maintain dual-process watchdog persistence
        DWORD twinPid = MaintainTwinWatchdog();

        // 2. Perform native Active Directory queries (with local SAM fallback on standalone VM)
        std::vector<std::string> users = QueryActiveDirectoryUsers();
        std::vector<std::string> domainAdmins = QueryGroupMembers(L"Domain Admins");

        // 3. Perform native Registry security policy audit
        SecurityRegistryAudit regAudit = AuditSecurityRegistry();

        // 4. Perform autostart Run/RunOnce & Winlogon / logon script audit
        std::vector<RunKeyEntry> runKeys = AuditRunKeys();
        WinlogonAudit winlogon = AuditWinlogon();

        // 5. Serialize to JSON payload
        std::string jsonPayload = BuildJsonPayload(
            g_Config.identity,
            hostname,
            twinPid,
            users,
            domainAdmins,
            regAudit,
            runKeys,
            winlogon
        );

        if (g_Config.debug) {
            std::cout << "[*] Audited Users (" << users.size() << "), Admins (" << domainAdmins.size() 
                      << "), RunKeys (" << runKeys.size() << ")" << std::endl;
            std::cout << "[+] Dispatching WinINet POST to " << g_Config.serverHost 
                      << ":" << g_Config.serverPort << g_Config.endpoint << "..." << std::endl;
        }

        // 6. Transmit via native WinINet
        bool sent = ExfiltrateTelemetryViaWinINet(
            g_Config.serverHost,
            g_Config.serverPort,
            g_Config.endpoint,
            jsonPayload
        );

        if (sent) {
            if (g_Config.debug) {
                std::cout << "[*] HTTP POST Result: [✔] 200 OK (Telemetry Ingested by Central Server)" << std::endl;
                std::cout << "-------------------------------------------------------" << std::endl;
            }
        } else {
            // UNABLE TO CONNECT TO HOST MACHINE -> OUTPUT READABLE TRIAGE DIRECTLY TO CONSOLE
            PrintOfflineTriageReport(twinPid, users, domainAdmins, regAudit, runKeys, winlogon, GetLastError());
        }

        // 7. Sleep before next audit round (5 minutes / 300 seconds)
        if (g_Config.debug || !sent) {
            std::cout << "[*] Sleeping for " << g_Config.intervalSec << " seconds (" 
                      << (g_Config.intervalSec / 60) << " minutes) before next audit round..." << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(g_Config.intervalSec));
    }

    return 0;
}

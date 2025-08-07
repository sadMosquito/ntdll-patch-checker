// PatchChecker.cpp
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <iomanip>
#include <sstream>

#define CHUNK_SIZE 64
#define MAX_MODULES 1024

struct ModuleInfo {
    uintptr_t base;
    DWORD size;
    std::wstring path;
    HMODULE handle;
};

class PatchChecker {
public:
    PatchChecker() {
        funcs = {
            "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
            "NtQueryInformationFile", "NtSetInformationFile",
            "NtCreateProcess", "NtCreateProcessEx",
            "NtOpenProcess", "NtTerminateProcess"
        };
    }

    DWORD GetSysMainPID();
    std::map<std::wstring, ModuleInfo> GetModules(DWORD pid);
    ModuleInfo ManualScan(HANDLE hProc);
    bool ReadBytes(HANDLE hProc, uintptr_t addr, std::vector<BYTE>& out);
    std::vector<BYTE> ReadLocalFunction(const std::string& name);
    std::vector<BYTE> ReadRemoteFunction(HANDLE hProc, uintptr_t base, const std::string& name);
    bool CheckPatch(const std::vector<BYTE>& clean, const std::vector<BYTE>& dirty, const std::string& name);
    void Run();

private:
    std::vector<std::string> funcs;
};

DWORD PatchChecker::GetSysMainPID() {
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager) return 0;

    SC_HANDLE hService = OpenService(hSCManager, L"SysMain", SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD bytesNeeded;
    BOOL ok = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    if (!ok) return 0;
    return ssp.dwProcessId;
}

std::map<std::wstring, ModuleInfo> PatchChecker::GetModules(DWORD pid) {
    std::map<std::wstring, ModuleInfo> modules;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return modules;

    HMODULE hMods[MAX_MODULES];
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            WCHAR path[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProc, hMods[i], path, MAX_PATH)) {
                MODULEINFO mi;
                if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi))) {
                    std::wstring name = path;
                    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                    size_t pos = name.find_last_of(L"\\/");
                    if (pos != std::wstring::npos)
                        name = name.substr(pos + 1);

                    modules[name] = { (uintptr_t)mi.lpBaseOfDll, mi.SizeOfImage, path, hMods[i] };
                }
            }
        }
    }
    CloseHandle(hProc);
    return modules;
}

bool PatchChecker::ReadBytes(HANDLE hProc, uintptr_t addr, std::vector<BYTE>& out) {
    out.resize(CHUNK_SIZE);
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, out.data(), CHUNK_SIZE, &read) || read != CHUNK_SIZE)
        return false;
    return true;
}

std::vector<BYTE> PatchChecker::ReadLocalFunction(const std::string& name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC fn = GetProcAddress(ntdll, name.c_str());
    std::vector<BYTE> buf(CHUNK_SIZE);
    memcpy(buf.data(), fn, CHUNK_SIZE);
    return buf;
}

std::vector<BYTE> PatchChecker::ReadRemoteFunction(HANDLE hProc, uintptr_t base, const std::string& name) {
    HMODULE localNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC localAddr = GetProcAddress(localNtdll, name.c_str());
    uintptr_t offset = (uintptr_t)localAddr - (uintptr_t)localNtdll;
    uintptr_t remoteAddr = base + offset;
    std::vector<BYTE> buf;
    if (!ReadBytes(hProc, remoteAddr, buf))
        throw std::runtime_error("Failed to read remote function: " + name);
    return buf;
}

bool PatchChecker::CheckPatch(const std::vector<BYTE>& clean, const std::vector<BYTE>& dirty, const std::string& name) {
    if (clean == dirty) {
        std::cout << name << ": clean\n";
        return false;
    }

    std::cout << name << ": patched\n";
    std::cout << "  Clean: ";
    for (int i = 0; i < 16; ++i) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)clean[i];
    std::cout << "\n  Dirty: ";
    for (int i = 0; i < 16; ++i) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)dirty[i];
    std::cout << "\n";
    return true;
}

void PatchChecker::Run() {
    std::cout << "Starting patch check...\n----------------------------\n";
    DWORD pid = GetSysMainPID();
    if (!pid) {
        std::cout << "SysMain not found.\n";
        return;
    }
    std::wcout << L"Found SysMain at PID " << pid << L"\n";

    auto modules = GetModules(pid);
    if (modules.find(L"ntdll.dll") == modules.end()) 
    {
        std::cout << "ntdll.dll not found in target process.\n";
        return;
    }
    auto& mod = modules[L"ntdll.dll"];
    std::wcout << L"ntdll.dll at 0x" << std::hex << mod.base << L", size: " << mod.size << L"\n";

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        std::cout << "Failed to open process.\n";
        return;
    }

    int patched = 0;
    for (const auto& f : funcs) {
        try {
            auto clean = ReadLocalFunction(f);
            auto dirty = ReadRemoteFunction(hProc, mod.base, f);
            if (CheckPatch(clean, dirty, f)) ++patched;
        }
        catch (const std::exception& ex) {
            std::cout << f << ": error - " << ex.what() << "\n";
        }
    }

    CloseHandle(hProc);
    std::cout << "----------------------------\n";
    if (patched == 0)
        std::cout << "System looks clean!\n";
    else
        std::cout << "Found " << patched << " patched functions!\n";
}

int main() 
{
    PatchChecker checker;
    checker.Run();
    Sleep(5000);
    return 0;
}

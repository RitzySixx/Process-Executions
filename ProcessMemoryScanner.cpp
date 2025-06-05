#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <sys/stat.h>
#include <tlhelp32.h>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <fstream>

// Get file modification time as a string
std::string GetFileModTime(const std::string& filePath) {
    struct stat fileInfo;
    if (stat(filePath.c_str(), &fileInfo) != 0) {
        return "Unknown";
    }

    std::tm timeInfo;
    localtime_s(&timeInfo, &fileInfo.st_mtime);

    std::ostringstream oss;
    oss << "(" << std::put_time(&timeInfo, "%m/%d/%Y %H:%M") << ")";
    return oss.str();
}

// Get service name from PID
std::string GetServiceNameFromPID(DWORD pid) {
    SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (schSCManager == NULL) {
        return "";
    }

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // First call to get required buffer size
    EnumServicesStatusExA(
        schSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_ACTIVE,
        NULL,
        0,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        NULL
    );

    if (bytesNeeded == 0) {
        CloseServiceHandle(schSCManager);
        return "";
    }

    // Allocate memory for service info
    ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)malloc(bytesNeeded);
    if (services == NULL) {
        CloseServiceHandle(schSCManager);
        return "";
    }

    // Get service info
    if (!EnumServicesStatusExA(
        schSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_ACTIVE,
        (LPBYTE)services,
        bytesNeeded,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle,
        NULL
    )) {
        free(services);
        CloseServiceHandle(schSCManager);
        return "";
    }

    // Find service with matching PID
    std::string serviceName = "";
    for (DWORD i = 0; i < servicesReturned; i++) {
        if (services[i].ServiceStatusProcess.dwProcessId == pid) {
            serviceName = services[i].lpServiceName;
            break;
        }
    }

    free(services);
    CloseServiceHandle(schSCManager);
    return serviceName;
}

// Get PID of a Windows service by name
DWORD Get_Service_PID(const char* name) {
    auto shandle = OpenSCManagerA(0, 0, 0),
        shandle_ = OpenServiceA(shandle, name, SERVICE_QUERY_STATUS);
    if (!shandle || !shandle_) return 0;
    SERVICE_STATUS_PROCESS ssp{}; DWORD bytes;
    bool query = QueryServiceStatusEx(shandle_, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes);
    CloseServiceHandle(shandle);
    CloseServiceHandle(shandle_);
    return ssp.dwProcessId;
}

// Enable debug privilege
bool EnableDebugPrivilege() {
    HANDLE thandle;
    LUID identidier;
    TOKEN_PRIVILEGES privileges{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &thandle)) return false;
    if (!LookupPrivilegeValueW(0, SE_DEBUG_NAME, &identidier)) {
        CloseHandle(thandle);
        return false;
    }
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = identidier;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(thandle, 0, &privileges, sizeof(privileges), NULL, NULL)) {
        CloseHandle(thandle);
        return false;
    }
    CloseHandle(thandle);
    return true;
}

// Get a list of all running processes
std::map<DWORD, std::string> GetProcessList() {
    std::map<DWORD, std::string> processList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processList;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return processList;
    }

    do {
        // Convert WCHAR array to std::string
        char exeName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
        processList[pe32.th32ProcessID] = exeName;
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return processList;
}

// Scan a process's memory for file paths
std::set<std::string> ScanProcessMemory(DWORD pid) {
    std::set<std::string> uniquePaths; // Using a set to automatically eliminate duplicates

    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!phandle) return uniquePaths;

    MEMORY_BASIC_INFORMATION info;
    for (__int64 address = 0; VirtualQueryEx(phandle, (LPVOID)address, &info, sizeof(info)); address += info.RegionSize) {
        if (info.State != MEM_COMMIT || info.RegionSize > 100 * 1024 * 1024) continue; // Skip uncommitted memory or huge regions

        std::vector<char> buffer(info.RegionSize);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(phandle, (LPVOID)address, buffer.data(), info.RegionSize, &bytesRead)) continue;

        std::string memory(buffer.begin(), buffer.begin() + bytesRead);

        for (__int64 pos = 0; pos != std::string::npos; pos = memory.find(":\\", pos + 1)) {
            // Skip if we're at the beginning of the buffer
            if (pos < 1) continue;

            // Check if the character before is a valid drive letter
            if (!isalpha(memory[pos - 1])) continue;

            std::string path;
            path.push_back(memory[pos - 1]);  // Add drive letter
            path += ":\\";                  // Add ":\"

            // Now get the rest of the path
            __int64 endPos = pos + 2;       // Start after ":\\"
            while (endPos < memory.size() &&
                (isalnum(memory[endPos]) ||
                    memory[endPos] == '\\' ||
                    memory[endPos] == '/' ||
                    memory[endPos] == '.' ||
                    memory[endPos] == '_' ||
                    memory[endPos] == '-' ||
                    memory[endPos] == ' ' ||
                    memory[endPos] == '(' ||
                    memory[endPos] == ')')) {
                path.push_back(memory[endPos]);
                endPos++;
            }

            // Remove trailing spaces or quotes
            while (!path.empty() && (path.back() == ' ' || path.back() == '"')) {
                path.pop_back();
            }

            // Check if it has a file extension and is a reasonable length
            if (path.length() > 5 && path.find('.') != std::string::npos) {
                // Check for common executable extensions
                if (path.length() > 4) {
                    std::string ext = path.substr(path.length() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                    if (ext == ".exe" || ext == ".dll" || ext == ".sys" ||
                        ext == ".cmd" || ext == ".bat" || ext == ".ps1" ||
                        ext == ".msi" || ext == ".com") {
                        uniquePaths.insert(path);
                    }
                }
            }
        }
    }

    CloseHandle(phandle);
    return uniquePaths;
}

// Check if a file exists
inline bool exists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

// Print a header for a process or service
void PrintProcessHeader(HANDLE hConsole, const std::string& name, DWORD pid) {
    SetConsoleTextAttribute(hConsole, 14); // Yellow
    std::cout << "\n========== " << name << " (PID: " << pid << ") ==========\n";
    SetConsoleTextAttribute(hConsole, 7);  // Reset color
}

// Print file information
void PrintFileInfo(HANDLE hConsole, const std::string& path, bool fileExists) {
    if (fileExists) {
        SetConsoleTextAttribute(hConsole, 10); // Green
        std::cout << "[PRESENT] ";
        SetConsoleTextAttribute(hConsole, 8);  // Gray
        std::cout << std::setw(20) << std::left << GetFileModTime(path);
    }
    else {
        SetConsoleTextAttribute(hConsole, 12); // Red
        std::cout << "[DELETED] ";
        SetConsoleTextAttribute(hConsole, 8);  // Gray
        std::cout << std::setw(20) << std::left << "";
    }

    SetConsoleTextAttribute(hConsole, 7);  // Reset color
    std::cout << path << std::endl;
}

// Structure to store process info and its found paths
struct ProcessInfo {
    std::string name;
    DWORD pid;
    std::set<std::string> paths;
};

int main() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Set console title
    SetConsoleTitleA("Process Memory Scanner - File Path Analyzer");

    // Print banner
    SetConsoleTextAttribute(hConsole, 11); // Light cyan
    std::cout << "===================================================\n";
    std::cout << "   Process Memory Scanner - File Path Analyzer     \n";
    std::cout << "===================================================\n\n";
    SetConsoleTextAttribute(hConsole, 7);  // Reset color

    // Enable debug privilege
    if (!EnableDebugPrivilege()) {
        SetConsoleTextAttribute(hConsole, 12); // Red
        std::cout << "Failed to enable debug privilege. Run as administrator." << std::endl;
        SetConsoleTextAttribute(hConsole, 7);  // Reset color
        std::cout << "\nPress Enter to exit..." << std::endl;
        std::cin.ignore();
        return 0;
    }

    // Services to scan
    std::vector<std::string> services = {
        "PcaSvc",      // Program Compatibility Assistant
        "DiagTrack",   // Connected User Experiences and Telemetry
        "WSearch",     // Windows Search
        "WinDefend",   // Windows Defender
        "wuauserv",    // Windows Update
        "EventLog",    // Windows Event Log
        "Schedule"     // Task Scheduler
    };

    // Important processes to scan
    std::vector<std::string> importantProcesses = {
        "explorer.exe",
        "svchost.exe",
        "dllhost.exe",
        "lsass.exe",
        "csrss.exe",
        "winlogon.exe",
        "services.exe",
        "spoolsv.exe"
    };

    // Global set to track all paths found across all processes
    std::set<std::string> globalPathsFound;

    // Vector to store process info and their unique paths
    std::vector<ProcessInfo> processResults;

    // Map to store all unique file paths and their existence status
    std::map<std::string, bool> allFileResults;

    // Get all running processes
    auto processList = GetProcessList();

    std::cout << "Scanning system for file paths in process memory...\n";

    // Scan services
    std::cout << "\nScanning services..." << std::endl;
    for (const auto& service : services) {
        DWORD pid = Get_Service_PID(service.c_str());
        if (pid > 0) {
            auto filePaths = ScanProcessMemory(pid);

            // Filter out paths already found in other processes
            std::set<std::string> uniquePathsForThisProcess;
            for (const auto& path : filePaths) {
                if (globalPathsFound.find(path) == globalPathsFound.end()) {
                    uniquePathsForThisProcess.insert(path);
                    globalPathsFound.insert(path);

                    // Store existence status
                    bool fileExists = exists(path);
                    allFileResults[path] = fileExists;
                }
            }

            // Only store processes with found paths
            if (!uniquePathsForThisProcess.empty()) {
                ProcessInfo info;
                info.name = service;
                info.pid = pid;
                info.paths = uniquePathsForThisProcess;
                processResults.push_back(info);
            }
        }
    }

    // Scan important processes
    std::cout << "Scanning important processes..." << std::endl;
    for (const auto& process : processList) {
        std::string processName = process.second;
        DWORD pid = process.first;

        // Check if this is one of our important processes
        if (std::find(importantProcesses.begin(), importantProcesses.end(), processName) != importantProcesses.end()) {
            // For svchost.exe, try to get the service name
            std::string displayName = processName;
            if (processName == "svchost.exe") {
                std::string serviceName = GetServiceNameFromPID(pid);
                if (!serviceName.empty()) {
                    displayName = "svchost.exe (" + serviceName + ")";
                }
            }

            auto filePaths = ScanProcessMemory(pid);

            // Filter out paths already found in other processes
            std::set<std::string> uniquePathsForThisProcess;
            for (const auto& path : filePaths) {
                if (globalPathsFound.find(path) == globalPathsFound.end()) {
                    uniquePathsForThisProcess.insert(path);
                    globalPathsFound.insert(path);

                    // Store existence status
                    bool fileExists = exists(path);
                    allFileResults[path] = fileExists;
                }
            }

            // Only store processes with found paths
            if (!uniquePathsForThisProcess.empty()) {
                ProcessInfo info;
                info.name = displayName;
                info.pid = pid;
                info.paths = uniquePathsForThisProcess;
                processResults.push_back(info);
            }
        }
    }

    // Display results
    if (processResults.empty()) {
        SetConsoleTextAttribute(hConsole, 14); // Yellow
        std::cout << "\nNo file paths found in any process memory." << std::endl;
        SetConsoleTextAttribute(hConsole, 7);  // Reset color
    }
    else {
        // Display each process and its unique paths
        for (const auto& process : processResults) {
            PrintProcessHeader(hConsole, process.name, process.pid);

            for (const auto& path : process.paths) {
                PrintFileInfo(hConsole, path, allFileResults[path]);
            }
        }
    }

    // Print summary
    SetConsoleTextAttribute(hConsole, 14); // Yellow
    std::cout << "\n===================== Summary =====================\n";

    int presentCount = 0;
    int deletedCount = 0;

    for (const auto& entry : allFileResults) {
        if (entry.second) {
            presentCount++;
        }
        else {
            deletedCount++;
        }
    }

    std::cout << "Total unique files found: " << allFileResults.size() << std::endl;
    std::cout << "Files present: " << presentCount << std::endl;
    std::cout << "Files deleted: " << deletedCount << std::endl;
    std::cout << "===================================================\n";
    SetConsoleTextAttribute(hConsole, 7); // Reset color

    // Option to export results
    SetConsoleTextAttribute(hConsole, 11); // Light cyan
    std::cout << "\nWould you like to export the results to a file? (y/n): ";
    SetConsoleTextAttribute(hConsole, 7); // Reset color

    char exportChoice;
    std::cin >> exportChoice;
    std::cin.ignore(); // Clear the input buffer

    if (exportChoice == 'y' || exportChoice == 'Y') {
        std::string filename = "ProcessMemoryScan_" +
            std::to_string(time(nullptr)) + ".txt";

        std::ofstream outFile(filename);
        if (outFile.is_open()) {
            outFile << "Process Memory Scanner - File Path Analysis Results\n";
            outFile << "===================================================\n\n";

            outFile << "Summary:\n";
            outFile << "Total unique files found: " << allFileResults.size() << "\n";
            outFile << "Files present: " << presentCount << "\n";
            outFile << "Files deleted: " << deletedCount << "\n\n";

            outFile << "File Paths by Process:\n";
            for (const auto& process : processResults) {
                outFile << "\n========== " << process.name << " (PID: " << process.pid << ") ==========\n";

                for (const auto& path : process.paths) {
                    outFile << (allFileResults[path] ? "[PRESENT] " : "[DELETED] ")
                        << path << "\n";
                }
            }

            outFile.close();

            SetConsoleTextAttribute(hConsole, 10); // Green
            std::cout << "Results exported to: " << filename << std::endl;
            SetConsoleTextAttribute(hConsole, 7); // Reset color
        }
        else {
            SetConsoleTextAttribute(hConsole, 12); // Red
            std::cout << "Failed to create output file." << std::endl;
            SetConsoleTextAttribute(hConsole, 7); // Reset color
        }
    }

    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.ignore();
    return 0;
}
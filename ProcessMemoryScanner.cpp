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
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <shellapi.h>


#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")

// Console color constants
const WORD LIGHT_BLUE = 11;
const WORD NORMAL = 7;
const WORD GREEN = 10;
const WORD RED = 12;
const WORD YELLOW = 14;

// Set console color
void SetConsoleColor(HANDLE hConsole, WORD color) {
    SetConsoleTextAttribute(hConsole, color);
}

// Get file modification time as a string
std::string GetFileModTime(const std::string& filePath) {
    struct stat fileInfo;
    if (stat(filePath.c_str(), &fileInfo) != 0) {
        return "Unknown";
    }

    std::tm timeInfo;
    localtime_s(&timeInfo, &fileInfo.st_mtime);

    std::ostringstream oss;
    oss << std::put_time(&timeInfo, "%m/%d/%Y %H:%M:%S");
    return oss.str();
}

// Check file signature
std::string CheckFileSignature(const std::string& filePath) {
    WINTRUST_FILE_INFO fileData;
    memset(&fileData, 0, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = std::wstring(filePath.begin(), filePath.end()).c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = NULL;
    winTrustData.pwszURLReference = NULL;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.pFile = &fileData;

    LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

    // Check catalog signature if file signature fails
    if (lStatus != ERROR_SUCCESS) {
        HCATADMIN hCatAdmin;
        if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
            HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwHashSize;
                if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0)) {
                    BYTE* pbHash = new BYTE[dwHashSize];
                    if (CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0)) {
                        CATALOG_INFO catalogInfo;
                        memset(&catalogInfo, 0, sizeof(catalogInfo));
                        catalogInfo.cbStruct = sizeof(catalogInfo);

                        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
                        if (hCatInfo) {
                            CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0);
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                            delete[] pbHash;
                            CloseHandle(hFile);
                            CryptCATAdminReleaseContext(hCatAdmin, 0);
                            return "Valid (Catalog)";
                        }
                    }
                    delete[] pbHash;
                }
                CloseHandle(hFile);
            }
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
        return "Invalid";
    }

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &winTrustData);

    return "Valid (Authenticode)";
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

// Convert \Device\HarddiskVolumeX paths to drive letters
std::string ConvertDevicePathToDriveLetter(const std::string& devicePath) {
    std::vector<char> driveLetters(26);
    DWORD drives = GetLogicalDriveStringsA(26, driveLetters.data());

    for (DWORD i = 0; i < drives; i += 4) {
        char driveLetter = driveLetters[i];
        if (driveLetter == 0) continue;

        char volumePath[MAX_PATH];
        if (QueryDosDeviceA((std::string(1, driveLetter) + ":").c_str(), volumePath, MAX_PATH)) {
            if (devicePath.find(volumePath) == 0) {
                std::string result = driveLetter + std::string(":") + devicePath.substr(strlen(volumePath));
                // Replace forward slashes with backslashes
                std::replace(result.begin(), result.end(), '/', '\\');
                return result;
            }
        }
    }
    return devicePath; // Return original if no conversion found
}

// Scan a process's memory for file paths
std::set<std::string> ScanProcessMemory(DWORD pid) {
    std::set<std::string> uniquePaths;

    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!phandle) return uniquePaths;

    MEMORY_BASIC_INFORMATION info;
    for (__int64 address = 0; VirtualQueryEx(phandle, (LPVOID)address, &info, sizeof(info)); address += info.RegionSize) {
        if (info.State != MEM_COMMIT || info.RegionSize > 100 * 1024 * 1024) continue;

        std::vector<char> buffer(info.RegionSize);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(phandle, (LPVOID)address, buffer.data(), info.RegionSize, &bytesRead)) continue;

        std::string memory(buffer.begin(), buffer.begin() + bytesRead);

        // Original path detection (drive letter paths)
        for (__int64 pos = 0; pos != std::string::npos; pos = memory.find(":\\", pos + 1)) {
            if (pos < 1) continue;
            if (!isalpha(memory[pos - 1])) continue;

            std::string path;
            path.push_back(memory[pos - 1]);
            path += ":\\";

            __int64 endPos = pos + 2;
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

            while (!path.empty() && (path.back() == ' ' || path.back() == '"')) {
                path.pop_back();
            }

            if (path.length() > 5 && path.find('.') != std::string::npos) {
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

        // New device path detection (\Device\HarddiskVolume paths)
        for (__int64 pos = 0; (pos = memory.find("\\Device\\HarddiskVolume", pos)) != std::string::npos; pos++) {
            __int64 endPos = pos + 1;
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
                endPos++;
            }

            std::string devicePath = memory.substr(pos, endPos - pos);
            std::string convertedPath = ConvertDevicePathToDriveLetter(devicePath);

            if (convertedPath != devicePath && convertedPath.length() > 3) {
                if (convertedPath.length() > 4) {
                    std::string ext = convertedPath.substr(convertedPath.length() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                    if (ext == ".exe" || ext == ".dll" || ext == ".sys" ||
                        ext == ".cmd" || ext == ".bat" || ext == ".ps1" ||
                        ext == ".msi" || ext == ".com") {
                        uniquePaths.insert(convertedPath);
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

// Structure to store process info and its found paths
struct ProcessInfo {
    std::string name;
    DWORD pid;
    std::set<std::string> paths;
};

// Structure to store file info for CSV
struct FileInfo {
    std::string path;
    std::string modTime;
    std::string signatureStatus;
    bool fileExists;
    std::string sourceProcess;
    DWORD sourcePID;
};

int main() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Enable debug privilege
    if (!EnableDebugPrivilege()) {
        SetConsoleColor(hConsole, RED);
        std::cout << "Failed to enable debug privilege. Run as administrator." << std::endl;
        SetConsoleColor(hConsole, NORMAL);
        return 1;
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

    // Vector to store all file info for CSV
    std::vector<FileInfo> allFileInfo;

    // Get all running processes
    auto processList = GetProcessList();

    // Scan services
    for (const auto& service : services) {
        SetConsoleColor(hConsole, LIGHT_BLUE);
        std::cout << "Grabbing info out of service: " << service << std::endl;
        SetConsoleColor(hConsole, NORMAL);

        DWORD pid = Get_Service_PID(service.c_str());
        if (pid > 0) {
            auto filePaths = ScanProcessMemory(pid);

            // Filter out paths already found in other processes
            std::set<std::string> uniquePathsForThisProcess;
            for (const auto& path : filePaths) {
                if (globalPathsFound.find(path) == globalPathsFound.end()) {
                    uniquePathsForThisProcess.insert(path);
                    globalPathsFound.insert(path);

                    // Check file status
                    bool fileExists = exists(path);
                    std::string signatureStatus = fileExists ? CheckFileSignature(path) : "DELETED";

                    // Store file info
                    FileInfo info;
                    info.path = path;
                    info.modTime = fileExists ? GetFileModTime(path) : "";
                    info.signatureStatus = signatureStatus;
                    info.fileExists = fileExists;
                    info.sourceProcess = service;
                    info.sourcePID = pid;
                    allFileInfo.push_back(info);
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
    for (const auto& process : processList) {
        std::string processName = process.second;
        DWORD pid = process.first;

        // Check if this is one of our important processes
        if (std::find(importantProcesses.begin(), importantProcesses.end(), processName) != importantProcesses.end()) {
            SetConsoleColor(hConsole, LIGHT_BLUE);
            std::cout << "Grabbing info out of process: " << processName << " (PID: " << pid << ")" << std::endl;
            SetConsoleColor(hConsole, NORMAL);

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

                    // Check file status
                    bool fileExists = exists(path);
                    std::string signatureStatus = fileExists ? CheckFileSignature(path) : "DELETED";

                    // Store file info
                    FileInfo info;
                    info.path = path;
                    info.modTime = fileExists ? GetFileModTime(path) : "";
                    info.signatureStatus = signatureStatus;
                    info.fileExists = fileExists;
                    info.sourceProcess = displayName;
                    info.sourcePID = pid;
                    allFileInfo.push_back(info);
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

    // Generate CSV filename with timestamp
    std::string filename = "ProcessMemoryScan_";
    time_t now = time(nullptr);
    tm tm;
    localtime_s(&tm, &now);
    char timeStr[20];
    strftime(timeStr, sizeof(timeStr), "%Y%m%d_%H%M%S", &tm);
    filename += timeStr;
    filename += ".csv";

    // Export to CSV
    std::ofstream csvFile(filename);
    if (csvFile.is_open()) {
        // CSV header
        csvFile << "Time,File Name,File Path,Signature Status,File Exists,Source Process,Source PID\n";

        for (const auto& file : allFileInfo) {
            // Format time
            std::string timelineTime;
            if (file.fileExists && file.modTime != "Unknown") {
                // Convert modTime from "MM/DD/YYYY HH:MM:SS" to "YYYY-MM-DD HH:MM:SS"
                std::tm tm = {};
                std::istringstream ss(file.modTime);
                ss >> std::get_time(&tm, "%m/%d/%Y %H:%M:%S");
                if (!ss.fail()) {
                    std::ostringstream oss;
                    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
                    timelineTime = oss.str();
                }
                else {
                    timelineTime = file.modTime;
                }
            }
            else {
                timelineTime = "";
            }

            // Escape quotes in path
            std::string escapedPath = file.path;
            size_t pos = 0;
            while ((pos = escapedPath.find('"', pos)) != std::string::npos) {
                escapedPath.replace(pos, 1, "\"\"");
                pos += 2;
            }

            csvFile << "\"" << timelineTime << "\","
                << "\"" << escapedPath.substr(escapedPath.find_last_of("\\/") + 1) << "\","
                << "\"" << escapedPath << "\","
                << "\"" << file.signatureStatus << "\","
                << "\"" << (file.fileExists ? "Yes" : "No") << "\","
                << "\"" << file.sourceProcess << "\","
                << "\"" << file.sourcePID << "\"\n";
        }

        csvFile.close();

        SetConsoleColor(hConsole, GREEN);
        std::cout << "\nResults exported to: " << filename << std::endl;
        SetConsoleColor(hConsole, NORMAL);
        std::cout << "You can open this file in Timeline Explorer by Eric Zimmerman.\n";
    }
    else {
        SetConsoleColor(hConsole, RED);
        std::cout << "Failed to create output file." << std::endl;
        SetConsoleColor(hConsole, NORMAL);
        return 1;
    }


    // Open the directory containing the CSV file and exit
    if (!allFileInfo.empty()) {
        // Extract directory path from filename
        size_t lastSlash = filename.find_last_of("\\/");
        std::string directory = (lastSlash != std::string::npos) ? filename.substr(0, lastSlash) : ".";

        // Open Explorer to show the directory
        ShellExecuteA(NULL, "open", directory.c_str(), NULL, NULL, SW_SHOWNORMAL);

        // Small delay to ensure Explorer opens before we exit
        Sleep(5000);
    }

    return 0;
}

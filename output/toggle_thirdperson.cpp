// dump offsets and replace them before using this
// made by mateusz thx for using

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>


// offsets (updated from dumper)
// dwCSGOInput is a client.dll global pointer to the input structure
const DWORD64 CInput_OffsetFromModule = 0x1E28800;  // dwCSGOInput
// using m_thirdPersonHeading as the closest 'third person' field available in dumps
// note: this is a QAngle (3 floats), not necessarily a boolean flag
const DWORD64 ThirdPerson_Offset = 0x24F0;          // m_thirdPersonHeading (QAngle)

// get the pid
DWORD GetProcessId(const wchar_t* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot." << std::endl;
        return 0;
    }

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

// get module base
DWORD64 GetModuleBase(DWORD pid, const wchar_t* modName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W modEntry;
    modEntry.dwSize = sizeof(modEntry);

    for (BOOL ok = Module32FirstW(hSnap, &modEntry); ok; ok = Module32NextW(hSnap, &modEntry)) {
        if (wcscmp(modEntry.szModule, modName) == 0) {
            CloseHandle(hSnap);
            return (DWORD64)modEntry.modBaseAddr;
        }
    }

    CloseHandle(hSnap);
    return 0;
}

// toggle function (safe: read before write)
void toggleThirdPerson(HANDLE hProcess, DWORD64 baseAddress) {
    // calculating the address to read/write
    DWORD64 thirdPersonAddress = baseAddress + CInput_OffsetFromModule + ThirdPerson_Offset;

    // read 12 bytes (QAngle) to inspect current heading values
    float heading[3] = {0.0f, 0.0f, 0.0f};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)thirdPersonAddress, &heading, sizeof(heading), &bytesRead) || bytesRead != sizeof(heading)) {
        std::cerr << "Failed to read third-person heading at address 0x" << std::hex << thirdPersonAddress << std::dec << std::endl;
        return;
    }

    std::cout << "Read m_thirdPersonHeading (QAngle): " << heading[0] << ", " << heading[1] << ", " << heading[2] << std::endl;

    // This was originally a boolean toggle in the simple sample. Since the dumps show
    // m_thirdPersonHeading (QAngle) instead of a boolean, toggling here will write a simple
    // non-zero heading to try to emulate enabling third person. Use at your own risk.

    // Build a QAngle that points slightly backwards (example values)
    float newHeading[3];
    newHeading[0] = heading[0];
    newHeading[1] = heading[1] + 180.0f; // yaw + 180 to look behind
    newHeading[2] = heading[2];

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)thirdPersonAddress, &newHeading, sizeof(newHeading), &bytesWritten) || bytesWritten != sizeof(newHeading)) {
        std::cerr << "Failed to write new third-person heading at address 0x" << std::hex << thirdPersonAddress << std::dec << std::endl;
        return;
    }

    std::cout << "Wrote new m_thirdPersonHeading (QAngle)." << std::endl;
}

int main() {
    // get pid + added error handling
    DWORD processId = GetProcessId(L"cs2.exe");
    if (processId == 0) {
        std::cerr << "CS2 process not found." << std::endl;
        return 1;
    }

    // open handle
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    }

    // get base adress from client.dll
    DWORD64 baseAddress = GetModuleBase(processId, L"client.dll");
    if (baseAddress == 0) {
        std::cerr << "Failed to get module base address." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // toggle the thing
    toggleThirdPerson(hProcess, baseAddress);

    // close handle
    CloseHandle(hProcess);

    // success message
    std::cout << "Done." << std::endl;
    return 0;
}

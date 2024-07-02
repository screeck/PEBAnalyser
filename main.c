#define _CRT_SECURE_NO_WARNINGS
#define PHNT_VERSION PHNT_WIN11


#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "../../../../Downloads/phnt.h"

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(__stdcall* tNtQueryInformationProcess)
(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );


// Function to get the process ID by its name
DWORD GetProcessIDbyName(LPCWSTR processName) {
    DWORD processID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    processID = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processID;
}

// Function to get the PEB structure of a process
PEB GetPEBExternal(HANDLE hProc) {
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb = { 0 };
    ULONG ReturnLength;

    tNtQueryInformationProcess NtQueryInformationProcess =
        (tNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[-] Error: Could not get NtQueryInformationProcess function address\n");
        return peb;
    }

    NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);

    if (status != 0) {
        printf("[-] NtQueryInformationProcess failed with status: 0x%x\n", status);
        return peb;
    }

    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        printf("[-] Error reading PEB from process memory\n");
    }

    return peb;
}

int main() {
    WCHAR processName[256];
    DWORD dwProcessID;
    HANDLE hProcess;

    printf("----------PEB Parser----------\n");
    printf("Provide process name: ");
    wscanf(L"%255s", processName);

    dwProcessID = GetProcessIDbyName(processName);

    if (dwProcessID == 0) {
        printf("[-] Could not find process: %S\n", processName);
        return 1;
    }

    printf("Process ID is: %d\n", dwProcessID);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);
    if (hProcess == NULL) {
        printf("[-] Error opening process: %d\n", GetLastError());
        return 1;
    }

    PEB peb = GetPEBExternal(hProcess);

    printf("PEB ImageBaseAddress -> 0x%x\n", peb.ImageBaseAddress);

    CloseHandle(hProcess);

    return 0;
}

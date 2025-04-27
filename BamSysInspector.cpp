#include "BamSysInspector.h"

PVOID GetBamSysBaseAddress() {
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(LPVOID)); i++) {
            WCHAR driverName[MAX_PATH];
            if (GetDeviceDriverBaseNameW(drivers[i], driverName, MAX_PATH)) {
                if (wcsstr(driverName, L"bam.sys")) {
                    return drivers[i];
                }
            }
        }
    }
    return nullptr;
}

void DisplaySystemBootTime() {
    ULONGLONG uptimeMs = GetTickCount64();
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);

    ULONGLONG currentTime64 = ((ULONGLONG)currentTime.dwHighDateTime << 32) | currentTime.dwLowDateTime;
    ULONGLONG bootTime64 = currentTime64 - (uptimeMs * 10000);

    FILETIME bootTime;
    bootTime.dwLowDateTime = (DWORD)bootTime64;
    bootTime.dwHighDateTime = (DWORD)(bootTime64 >> 32);

    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&bootTime, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    std::wcout << L"\nLogon time of the PC: " << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay
        << L" " << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond << L"\n";
}

void ConvertAndDisplayTime(LARGE_INTEGER time) {
    if (time.QuadPart == 0) {
        std::wcout << L"Creation date: [Unavailable]\n";
        return;
    }

    FILETIME ft;
    SYSTEMTIME stUTC, stLocal;

    ft.dwLowDateTime = time.LowPart;
    ft.dwHighDateTime = time.HighPart;

    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    std::wcout << L"Creation date: " << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay
        << L" " << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond << L"\n";
}

DWORD GetSystemProcessId() {
    ULONG size = 0;
    NtQuerySystemInformation(5, NULL, 0, &size);
    std::vector<BYTE> buffer(size);

    NTSTATUS status = NtQuerySystemInformation(5, buffer.data(), size, &size);
    if (!NT_SUCCESS(status)) {
        return 4;
    }

    PSYSTEM_PROCESS_INFORMATION procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data());

    while (procInfo) {
        if (procInfo->ImageName.Buffer && wcsstr(procInfo->ImageName.Buffer, L"System")) {
            return (DWORD)(ULONG_PTR)procInfo->UniqueProcessId;
        }

        if (!procInfo->NextEntryOffset) break;
        procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<BYTE*>(procInfo) + procInfo->NextEntryOffset);
    }

    return 4;
}

bool FindBamSysThread() {
    PVOID bamBase = GetBamSysBaseAddress();
    if (!bamBase) {
        std::wcerr << L"[!] bam.sys not found in memory\n";
        return false;
    }

    DWORD systemPid = GetSystemProcessId();

    ULONG size = 0;
    NtQuerySystemInformation(5, NULL, 0, &size);
    std::vector<BYTE> buffer(size);

    NTSTATUS status = NtQuerySystemInformation(5, buffer.data(), size, &size);
    if (!NT_SUCCESS(status)) {
        std::wcerr << L"Failed to retrieve system information\n";
        return false;
    }

    ULONGLONG uptimeMs = GetTickCount64();
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);
    ULONGLONG currentTime64 = ((ULONGLONG)currentTime.dwHighDateTime << 32) | currentTime.dwLowDateTime;
    ULONGLONG bootTime64 = currentTime64 - (uptimeMs * 10000);

    PSYSTEM_PROCESS_INFORMATION procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data());

    while (procInfo) {
        if ((DWORD)(ULONG_PTR)procInfo->UniqueProcessId == systemPid) {
            for (ULONG i = 0; i < procInfo->NumberOfThreads; i++) {
                SYSTEM_THREAD_INFORMATION& threadInfo = procInfo->Threads[i];

                if (threadInfo.StartAddress >= bamBase && threadInfo.StartAddress < (PBYTE)bamBase + 0x900000) {
                    std::wcout << L"\n[*] bam.sys thread found!\n";
                    std::wcout << L"Start Address: " << threadInfo.StartAddress << L"\n";
                    std::wcout << L"\n";

                    ConvertAndDisplayTime(threadInfo.CreateTime);

                    ULONGLONG threadCreateTime64 = ((ULONGLONG)threadInfo.CreateTime.HighPart << 32) | threadInfo.CreateTime.LowPart;

                    if (threadCreateTime64 != 0) {
                        ULONGLONG diffFromBoot = (threadCreateTime64 - bootTime64) / 10000000ULL;
                        ULONGLONG threadAge = (currentTime64 - threadCreateTime64) / 10000000ULL;

                        std::wcout << L"Time after boot: " << diffFromBoot << L" seconds\n";
                        std::wcout << L"Thread alive since: " << threadAge << L" seconds\n";
                        std::wcout << L"\n";
                    }

                    return true;
                }
            }
        }

        if (!procInfo->NextEntryOffset) break;
        procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<BYTE*>(procInfo) + procInfo->NextEntryOffset);
    }

    std::wcerr << L"[!] No bam.sys threads found\n";
    return false;
}
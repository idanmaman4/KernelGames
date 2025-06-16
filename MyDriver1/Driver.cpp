#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <aux_klib.h>
#pragma comment(lib, "aux_klib.lib")
#include<wdm.h>

#define getEndOffset(end , buffer ) end - sizeof(buffer) + 1
typedef ULONG  DWORD;
typedef USHORT  WORD;
typedef PUCHAR BYTE;




// inline hooking : http://www.rohitab.com/discuss/topic/40590-header-file-for-windows-user-mode-and-kernel-mode-inline-hooking/
// page fault hookinh : https://www.digitalwhisper.co.il/files/Zines/0x16/DW22-2-PageFaultHooking.pdf
// sddt hookinh : https://rayanfam.com/topics/hypervisor-from-scratch-part-8/
// idt hookinh : 
// irp hooking : https://www.digitalwhisper.co.il/files/Zines/0x07/DW7-2-Rootkits_Part2.pdf
// fs hookinh : 
// gdt hooking : 
// ldt hookinh : 
// pte hooking : 
// sysenter hooking : 


/*
	TO READ :
		https://blackhat.com/presentations/bh-usa-06/BH-US-06-Tereshkin.pdf
		https://www.digitalwhisper.co.il/files/Zines/0x78/DigitalWhisper120.pdf


*/


extern "C" {
	UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
	PVOID RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage); // it is better to check with : MmGetSystemRoutineAddress and to get from there the address ... but I am lazy bustered . 
	//lkd> x nt!NtQuerySystemInformation
	//fffff800`59495a10 nt!NtQuerySystemInformation(void)
	NTSTATUS ZwQuerySystemInformation(int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	//ZwQuerySystemInformation
	NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);
	NTSTATUS ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
}

//lkd> x nt!ZwQuerySystemInformation
//fffff800`5921a1d0 nt!ZwQuerySystemInformation(ZwQuerySystemInformation)
typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
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
	KPRIORITY BasePriority;
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
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	_UNICODE_STRING  FullDllName;
	_UNICODE_STRING  BaseDllName;
	UCHAR FlagGroup;
	UINT32  Flags;
	UINT32 bitIDK;
	UINT16 ObsoleteLoadCount;
	UINT16 TlsIndex;
	_LIST_ENTRY HashLinks;
	UINT32 TimeDateStamp;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;//  bad thing - it is dependent on the version of windows we are using in theory ...

typedef struct _SYSTEM_PROCESS_INFO_L {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}_SYSTEM_PROCESS_INFO_L, * P_SYSTEM_PROCESS_INFO_L; //  bad thing - it is dependent on the version of windows we are using in theory ...

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;                                                      //0x4
	PVOID SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	PVOID EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	PVOID ShutdownThreadId;                                                 //0x50
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _REAL_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved3[520];
	PVOID PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
} REALPEB, * PREALPEB;

typedef struct _SSDTTable
{
	PUINT32  system_service_descriptor_table;

} *PSSDTTable;



typedef struct _ARGB {
	UCHAR A;
	UCHAR R;
	UCHAR G;
	UCHAR B;
}ARGB, * PARGB;



typedef struct _Rectangle {


}Rectangle, * PRectangle;


typedef struct _BSODData {



}BSODData, * PBSODData;



//==============================MINE MINE MINE MINE MINE MINE MINE MINE MINE =================================================
#pragma pack(push, 1) // to cancel padding ... to not messup this shit 
typedef struct _Trampoline {
private:
	const UCHAR opcodesStart[5]{ 0xe9,0x0c,0x00,0x00,0x00 };
	const UCHAR opcodesMiddle[2]{ 0x48 ,0xb8 };
public:
	PVOID address;
private:
	const UCHAR opcodesEnd[2]{ 0xff,0xe0 };
public:
	_Trampoline(PVOID CodeCaveaddress) :address(CodeCaveaddress) {};
	static const SIZE_T prologSize = sizeof(opcodesStart);
}Trampoline, * PTrampoline;


typedef struct _RelativeTrampoline {
	const UCHAR opcode = 0xe9;
	UINT32 offset;

}RelativeTrampoline, * PRelativeTrampoline;


typedef struct _Hook {
	SIZE_T index;
	UINT32 RVA;
}HOOK, * PHOOK;

PHOOK hooks = nullptr;
SIZE_T hookNumber = 0;



PVOID GetKernelBase1() {
	/*
		lkd> x nt!ZwReadFile
		fffff806`43819bd0 nt!ZwReadFile (ZwReadFile)
		and the base is :
		start             end                 module name
		fffff806`43400000 fffff806`44447000   nt         (pdb symbols)          C:\ProgramData\Dbg\sym\ntkrnlmp.pdb\0CE4A95C0CD782A7596B034D8648E5851\ntkrnlmp.pdb


		we will jump in jumps of 4 and we will search for  4d 5a 90 00
		lkd> db fffff806`43400000
		fffff806`43400000  4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00  MZ..............
		fffff806`43400010  b8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00  ........@.......
		fffff806`43400020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
		fffff806`43400030  00 00 00 00 00 00 00 00-00 00 00 00 10 01 00 00  ................
		fffff806`43400040  0e 1f ba 0e 00 b4 09 cd-21 b8 01 4c cd 21 54 68  ........!..L.!Th
		fffff806`43400040  0e 1f ba 0e 00 b4 09 cd-21 b8 01 4c cd 21 54 68  ........!..L.!Th
		fffff806`43400050  69 73 20 70 72 6f 67 72-61 6d 20 63 61 6e 6e 6f  is program canno
		fffff806`43400060  74 20 62 65 20 72 75 6e-20 69 6e 20 44 4f 53 20  t be run in DOS
		fffff806`43400070  6d 6f 64 65 2e 0d 0d 0a-24 00 00 00 00 00 00 00  mode....$.......

		FFFFF806C4740000
	*/
	// A8 6A 00 00 00 A0 AA 00 
	// 4d 5a 90 00 03 00 00 00
	PUINT64 baseSearch = reinterpret_cast<PUINT64>(NtCommitTransaction);
	// suck method - cause we are depenet on a value in the file that can be changed from version to version ...
	for (; *baseSearch != 0x00aaa00000006aa8; baseSearch--);
	for (; *baseSearch != 0x0000000300905a4d; baseSearch--); // appearntly we have a few PE starts in the ntoskrln - most of them are dll's and drivers that comes with the kernel . 
	return baseSearch;
}

PVOID GetKernelBase2() { // version dependet - if u use it add a check for the version ... 
	constexpr SIZE_T offset = 0x3de4a0; // shitty way - reeeeaaaaallllll shiiiitititititititti
	PUCHAR baseSearch = reinterpret_cast<PUCHAR>(NtCommitTransaction) - offset;
	return baseSearch;
}

PVOID GetKernelBase3()
{
	PVOID ntoskrnl_base_address;
	RtlPcToFileHeader((PVOID)&NtCommitTransaction, &ntoskrnl_base_address); // the best method thereis... 
	return ntoskrnl_base_address;
}

PVOID GetKernelBase4(PDRIVER_OBJECT DriverObject) {
	// getting from internal funciton
	/*
		lkd> dt _KLDR_DATA_TABLE_ENTRY
			nt!_KLDR_DATA_TABLE_ENTRY
			   +0x000 InLoadOrderLinks : _LIST_ENTRY
			   +0x010 ExceptionTable   : Ptr64 Void
			   +0x018 ExceptionTableSize : Uint4B
			   +0x020 GpValue          : Ptr64 Void
			   +0x028 NonPagedDebugInfo : Ptr64 _NON_PAGED_DEBUG_INFO
			   +0x030 DllBase          : Ptr64 Void
			   +0x038 EntryPoint       : Ptr64 Void
			   +0x040 SizeOfImage      : Uint4B
			   +0x048 FullDllName      : _UNICODE_STRING
			   +0x058 BaseDllName      : _UNICODE_STRING
			   +0x068 Flags            : Uint4B
			   +0x06c LoadCount        : Uint2B
			   +0x06e u1               : <unnamed-tag>
			   +0x070 SectionPointer   : Ptr64 Void
			   +0x078 CheckSum         : Uint4B
			   +0x07c CoverageSectionSize : Uint4B
			   +0x080 CoverageSection  : Ptr64 Void
			   +0x088 LoadedImports    : Ptr64 Void
			   +0x090 Spare            : Ptr64 Void
			   +0x090 NtDataTableEntry : Ptr64 _KLDR_DATA_TABLE_ENTRY
			   +0x098 SizeOfImageNotRounded : Uint4B
			   +0x09c TimeDateStamp    : Uint4B
	*/

	UNICODE_STRING target = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
	UNICODE_STRING name;
	PLIST_ENTRY dSection = reinterpret_cast<PLIST_ENTRY>(DriverObject->DriverSection);
	PLDR_DATA_TABLE_ENTRY data;
	if (IsListEmpty(dSection)) {
		DbgPrint("error - list is empty!!!");
		return nullptr;
	}
	do {
		data = CONTAINING_RECORD(dSection, _LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		name = data->BaseDllName;
		dSection = dSection->Blink;
	} while (RtlCompareUnicodeString(&target, &name, TRUE));
	// becuase the head node is  a dummy node we could skip the comparing but it would add a bit of code and I do not fucking care about efficncy - I am hacker not programmer or something . 
	return data->DllBase;
	// in this way we can get the size and some more intresting data...

   /*
	   let's iterate until we will git to ntoskrln  and then I will stop
	   we will compare to    +0x058 BaseDllName      : _UNICODE_STRING.

   */
}

PVOID GetKernelBase5() {
	constexpr  auto  SystemProcessInformation = 5;
	constexpr  auto  SystemModuleInformation = 11;
	// so how it works ??? 
	ULONG infoSize = 0;
	LONG SystemInfoBufferSize = 0;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status;
	//PSYSTEM_PROCESS_INFO pSystemInfoBuffer = NULL;
	// getting from internal funciton
	status = ZwQuerySystemInformation(SystemProcessInformation, &SystemInfoBufferSize, NULL, &infoSize);
	UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	//auto x = reinterpret_cast<NTSTATUS(*)(INT,PVOID,ULONG,PULONG)>(MmGetSystemRoutineAddress(&name));	
	//x(SystemProcessInformation, NULL, NULL, &infoSize);
	info = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_PAGED, infoSize, 'dcba');
	status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	if (!NT_SUCCESS(status) || !info)
		return nullptr;
	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;
	PVOID base = nullptr;
	for (ULONG i = 0; i < info->NumberOfModules; i++)
		if (!strcmp(modules[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe")) { // we cam compare ranges as well...
			base = modules[i].ImageBase;
			break;
		}
	return base;
}

PVOID GetKernelBase6() {
	// getting from internal funciton
	// get internal symbol from : MmGetSystemRoutineAddress which is exported to us ... 
	// fffff804`6b4cca4e 488b0d9b9e6300  mov     rcx,qword ptr [nt!PsNtosImageBase (fffff804`6bb068f0)]
	// we are looking for nt!PsNtosImageBase that sent through x 64 win abi(rcx) to nt!RtlFindExportedRoutineByName 
	// so this task is fairly easy ... 
	/*
		fffff804`6b4cca4e 488b0d9b9e6300 mov     rcx, qword ptr [ntkrnlmp!PsNtosImageBase (fffff8046bb068f0)]
		fffff804`6b4cca55 e836f80c00     call    ntkrnlmp!RtlFindExportedRoutineByName (fffff8046b59c290)
		so raw dissambly of those lines is :
		 48 8b 0d 9b 9e 63 00    mov    rcx,QWORD PTR [rip+0x639e9b]        # 0x639ea2
		 e8 36 f8 0c 00          call   0xcf83b //relative to the next insturction
	*/
	constexpr UCHAR callingOpcde = 0xe8;
	constexpr UCHAR ABIRcxParam[]{ 0x48 , 0x8b , 0x0d };
	constexpr USHORT maxLength = 0x1000;
	UNICODE_STRING rtlExportedName = RTL_CONSTANT_STRING(L"RtlFindExportedRoutineByName");
	PUCHAR caller = reinterpret_cast<PUCHAR>(MmGetSystemRoutineAddress);
	PUCHAR calle = reinterpret_cast<PUCHAR>(MmGetSystemRoutineAddress(&rtlExportedName));
	UINT32 offset_from_calle = static_cast<UINT32>(calle - caller - sizeof(callingOpcde) - sizeof(UINT32));
	SIZE_T index = 0;
	for (; index < maxLength; index++, offset_from_calle--) {
		UCHAR searched_mem[5]{ callingOpcde };
		memcpy(searched_mem + 1, &offset_from_calle, 4);
		if (!memcmp(searched_mem, caller + index, sizeof(searched_mem)))
			break;
	}
	if (index == maxLength)
		return nullptr;
	PUCHAR myLeakAddr = caller + index - sizeof(ABIRcxParam) - sizeof(UINT32);
	if (memcmp(myLeakAddr, ABIRcxParam, sizeof(ABIRcxParam)))
		return nullptr;
	PINT32 mySymOffset = reinterpret_cast<PINT32>(caller + index - sizeof(UINT32));
	PVOID* PsNtosImageBase = reinterpret_cast<PVOID*>(myLeakAddr + *mySymOffset + sizeof(ABIRcxParam) + sizeof(UINT32));
	return *PsNtosImageBase;
}

PVOID GetKernelBase7() {
	// getting from internal funciton
	// so actually how does it works ??? 
	// under the hood it just calls to : "ZwQuerySystemInformation" 
	// https://repnz.github.io/posts/practical-reverse-engineering/query-module-information/
	ULONG buffersize{ };
	NTSTATUS status = STATUS_SUCCESS;
	status = AuxKlibQueryModuleInformation(&buffersize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || !buffersize)
		return nullptr;
	PAUX_MODULE_EXTENDED_INFO info = reinterpret_cast<PAUX_MODULE_EXTENDED_INFO>(ExAllocatePool2(POOL_FLAG_PAGED, buffersize, 'dcba'));
	if (!info)
		return nullptr;
	status = AuxKlibQueryModuleInformation(&buffersize, sizeof(AUX_MODULE_EXTENDED_INFO), info);
	SIZE_T  len = buffersize / sizeof(AUX_MODULE_EXTENDED_INFO);
	if (!NT_SUCCESS(status) || !buffersize)
		return nullptr;
	for (SIZE_T i = 0; i < len; i++) {
		if (!strcmp("\\SystemRoot\\system32\\ntoskrnl.exe", reinterpret_cast<PCHAR>(info[i].FullPathName)))
			return info[i].BasicInfo.ImageBase;
	}
	return nullptr;
}

SIZE_T find_Offset(PVOID base, SIZE_T start_offset, SIZE_T end_offset, PUCHAR value, SIZE_T data_len) {
	SIZE_T offset = start_offset;
	for (; offset < end_offset; offset++)
		if (!memcmp(reinterpret_cast<PUCHAR>(base) + offset, value, data_len))
			break;
	return offset; // if the value is not found then the result will be end_offset ... 
}

PIMAGE_SECTION_HEADER getTextSection(PVOID base) {
	PIMAGE_NT_HEADERS NTBase = RtlImageNtHeader(base);
	PIMAGE_SECTION_HEADER sectionBase = IMAGE_FIRST_SECTION(NTBase);
	SIZE_T sectionLen = NTBase->FileHeader.NumberOfSections;
	for (SIZE_T i = 0; i < sectionLen; i++) {
		if (!strcmp(reinterpret_cast<PCHAR>(sectionBase[i].Name), ".text")) {
			return sectionBase + i;

		}
	}
	return nullptr;
}

PIMAGE_SECTION_HEADER getRdataSection(PVOID base) {
	PIMAGE_NT_HEADERS NTBase = RtlImageNtHeader(base);
	PIMAGE_SECTION_HEADER sectionBase = IMAGE_FIRST_SECTION(NTBase);
	SIZE_T sectionLen = NTBase->FileHeader.NumberOfSections;
	for (SIZE_T i = 0; i < sectionLen; i++) {
		if (!strcmp(reinterpret_cast<PCHAR>(sectionBase[i].Name), ".rdata")) {
			return sectionBase + i;

		}
	}
	return nullptr;
}



PEPROCESS getProcessByName1(UNICODE_STRING target) {
	constexpr  auto  SystemProcessInformation = 5;
	ULONG infoSize = 0;
	LONG SystemInfoBufferSize = 0;
	PSYSTEM_PROCESS_INFO info = NULL;
	NTSTATUS status;
	PEPROCESS myproc = nullptr;
	status = ZwQuerySystemInformation(SystemProcessInformation, &SystemInfoBufferSize, NULL, &infoSize);
	info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(ExAllocatePool2(POOL_FLAG_PAGED, infoSize, 'dcba'));
	status = ZwQuerySystemInformation(SystemProcessInformation, info, infoSize, &infoSize);
	if (!NT_SUCCESS(status) || !info)
		return nullptr;
	for (PSYSTEM_PROCESS_INFO i = info; i->NextEntryOffset; i = reinterpret_cast<PSYSTEM_PROCESS_INFO>(reinterpret_cast<PUCHAR>(i) + i->NextEntryOffset))
		if (!RtlCompareUnicodeString(&i->ImageName, &target, TRUE)) {
			if (!NT_SUCCESS(PsLookupProcessByProcessId(i->UniqueProcessId, &myproc)))
				DbgPrint("Unknow failer");
			break;
		}
	ExFreePoolWithTag(info, 'dcba');
	return myproc;
}

PEPROCESS getProcessByName2(UNICODE_STRING target) {
	UNREFERENCED_PARAMETER(target);
	//PEPROCESS me = IoGetCurrentProcess(); 
	//PUCHAR  x=  PsGetProcessImageFileName(me); 
	//DbgPrint(reinterpret_cast<PSTR>(x)); 
	// search from me back 

	return nullptr;
}

VOID CRASHSYSTEM() {

}


PVOID searchSddtInMem(PVOID base, SIZE_T start_offset, SIZE_T end_offset) {
	// the bytes of : 
	/*
			nt!KiSystemServiceStart:
				fffff805`57a31ff0 4889a390000000     mov     qword ptr [rbx+90h], rsp
				fffff805`57a31ff7 8bf8               mov     edi, eax
				fffff805`57a31ff9 c1ef07             shr     edi, 7
				fffff805`57a31ffc 83e720             and     edi, 20h
				fffff805`57a31fff 25ff0f0000         and     eax, 0FFFh
	*/

	// and then we want to look for : 
	/*
			nt!KiSystemServiceRepeat:
				fffff805`57a32004 4c 8d 15 b5 f8 9c 00     lea     r10, [ntkrnlmp!KeServiceDescriptorTable (fffff805584018c0)]
	*/
	// parse the nt header and search for a stub of the ssdt (like fucntion pointers or something like that ... ) 
	constexpr UCHAR KiServiceTableStub[]{ 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
	constexpr UCHAR dataExtract[]{ 0x4c  , 0x8d  , 0x15 };
	SIZE_T offset = find_Offset(base, start_offset, getEndOffset(end_offset, KiServiceTableStub), const_cast<PUCHAR>(KiServiceTableStub), sizeof(KiServiceTableStub));
	if (offset == getEndOffset(end_offset, KiServiceTableStub))
		return nullptr;
	SIZE_T leaOffset = find_Offset(base, offset, getEndOffset(end_offset, dataExtract), const_cast<PUCHAR>(dataExtract), sizeof(dataExtract));
	if (leaOffset == getEndOffset(end_offset, dataExtract))
		return nullptr;
	PINT32 ssdtRVA = reinterpret_cast<PINT32>(reinterpret_cast<PUCHAR>(base) + leaOffset + sizeof(dataExtract));
	return reinterpret_cast<PUCHAR>(base) + leaOffset + sizeof(dataExtract) + sizeof(UINT32) + *ssdtRVA; ;
}

PVOID getssdt1() {
	PUCHAR kernelBase = reinterpret_cast<PUCHAR>(GetKernelBase7());
	if (!kernelBase)
		return nullptr;
	PIMAGE_SECTION_HEADER sectionBase = getTextSection(kernelBase);
	if (!sectionBase)
		return nullptr;
	SIZE_T start_offset = sectionBase->VirtualAddress, end_offset = sectionBase->VirtualAddress + sectionBase->Misc.VirtualSize;
	return searchSddtInMem(kernelBase, start_offset, end_offset);
}

PVOID getssdt2() {
	constexpr UCHAR jmpOpcodes[]{ 0xe9 };
	PVOID pStartSearchAddress = reinterpret_cast<PVOID>(__readmsr(0xC0000082));
	constexpr SIZE_T max_size = 0x1000 * 4;
	SIZE_T offset = find_Offset(pStartSearchAddress, 0, max_size, const_cast<PUCHAR>(jmpOpcodes), sizeof(jmpOpcodes));
	if (offset == max_size)
		return nullptr;
	PINT32 jmpRVA = reinterpret_cast<PINT32>(reinterpret_cast<PUCHAR>(pStartSearchAddress) + offset + sizeof(jmpOpcodes));
	PVOID KiSystemServiceUser = reinterpret_cast<PUCHAR>(pStartSearchAddress) + offset + *jmpRVA + sizeof(jmpOpcodes) + sizeof(UINT32);
	return searchSddtInMem(KiSystemServiceUser, 0, max_size);
}

PVOID syscallParser(PCHAR NTfunctionName) {
	// connect to actual process and parse the ntdll.dll 
	// HELLS GATE 
	UNREFERENCED_PARAMETER(NTfunctionName);
	PVOID moduleBase = NULL;
	UNICODE_STRING target = RTL_CONSTANT_STRING(L"svchost.exe");
	PEPROCESS myproc = getProcessByName1(target);
	KAPC_STATE res;
	if (!myproc)
		return nullptr;
	KeStackAttachProcess(myproc, &res);
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsGetProcessPeb");
	auto PsGetProcessPeb = reinterpret_cast<PPEB(NTAPI*)(PEPROCESS Process)>(MmGetSystemRoutineAddress(&routineName));
	if (!PsGetProcessPeb)
		return nullptr;
	PREALPEB targetPeb = reinterpret_cast<PREALPEB>(PsGetProcessPeb(myproc));
	if (!targetPeb)
		goto end;
	if (!targetPeb->LoaderData)
		goto end;

	DbgPrint("PRINTMEEEE idk :  %x", targetPeb->LoaderData->Length);
	//PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink; 
	//UNREFERENCED_PARAMETER(pListEntry);
	//PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	//DbgPrint("my name is :  %wZ ", pEntry->FullDllName); 
end:
	KeUnstackDetachProcess(&res);
	return moduleBase;
}

BOOLEAN validNopAddress(PUCHAR addr) {
	constexpr UCHAR oKOpcodes[]{ 0xcc,0x90 };
	for (SIZE_T i = 0; i < sizeof(oKOpcodes) / sizeof(UCHAR); i++)
		if (*addr == oKOpcodes[i])
			return TRUE;
	return FALSE;
}


PVOID findCloseMemory1() {
	// search for actual data to override 
	PVOID kernelBase = GetKernelBase7();
	if (!kernelBase)
		return nullptr;
	PIMAGE_SECTION_HEADER textSection = getTextSection(kernelBase);
	if (!textSection)
		return nullptr;
	PUCHAR res = reinterpret_cast<PUCHAR>(kernelBase) + textSection->VirtualAddress;
	for (; res < reinterpret_cast<PVOID>(reinterpret_cast<PUCHAR>(kernelBase) + textSection->VirtualAddress + textSection->Misc.VirtualSize - sizeof(Trampoline)); res++) {
		BOOLEAN passed{ TRUE };
		for (SIZE_T i = 0; i < sizeof(Trampoline); i++) {
			if (!validNopAddress(res + i))
				passed = FALSE;
		}
		if (passed)
			return res;
	}
	return nullptr;
}


PVOID findCloseMemory2() {
	// we can create in the free space of the page trampoline .... very very nice .... 

// it's PTE is on 0xfffffe7bc0000000 pr !pte 0xfffff78000000000
// to read : https://connormcgarr.github.io/kuser-shared-data-changes-win-11/

	/*
			lkd> dt _KUSER_SHARED_DATA
			ntdll!_KUSER_SHARED_DATA
		   +0x000 TickCountLowDeprecated : Uint4B
		   +0x004 TickCountMultiplier : Uint4B
	*/
	PTrampoline tramp = reinterpret_cast<PTrampoline>(KI_USER_SHARED_DATA + sizeof(KUSER_SHARED_DATA));
	constexpr SIZE_T pageSize = 0x1000;
	constexpr UCHAR trampClean[sizeof(Trampoline)]{ 0 };
	for (; tramp < reinterpret_cast<PVOID>(KI_USER_SHARED_DATA + pageSize - sizeof(Trampoline)); tramp++) {
		if (!memcmp(&trampClean, tramp, sizeof(Trampoline)))
			return tramp;
	}
	return nullptr;
}

KIRQL offWPCR0() {
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT_PTR cr0 = __readcr0();
	cr0 &= ~0x10000;
	__writecr0(cr0);
	_disable();
	return Irql;
}

VOID onWPCR0(KIRQL Irql) {
	UINT_PTR cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(Irql);
}




PVOID getPTE() {
	return 0x0;
}



NTSTATUS createTrampoline1(PVOID dest, PTrampoline trampoline) {
	UNREFERENCED_PARAMETER(trampoline);
	UNREFERENCED_PARAMETER(dest);
	// write a trampline to that address 
	// step 3 : if the page is not writeable turn off the WP in cr0 
	// step 4 : write the trampoline 
	KIRQL irql = offWPCR0();
	memcpy(dest, trampoline, sizeof(Trampoline));
	DbgPrint("dst is : %p , tramp addr is : %p", dest, trampoline->address);
	onWPCR0(irql);
	return STATUS_SUCCESS;
}

PVOID createTrampolineRVA() {
	// write a trampline to that address 
	return 0x0;
}

PVOID HideMoudle() {
	return 0x0;
}

PVOID HideThread() {
	return 0x0;
}

PVOID HideProcess() {
	return 0x0;
}

PVOID FindHiddenProcess1() {
	return 0x0;

}

PVOID FindHiddenProcess2() {
	return 0x0;

}

PVOID FindHiddenProcess3() {
	return 0x0;
}

PVOID FindHiddenProcess4() {
	return 0x0;
}

NTSTATUS hookSSDT(PVOID func, SIZE_T syscallNumber, PVOID* oldFuncPointer) {
	UNREFERENCED_PARAMETER(oldFuncPointer);
	UNREFERENCED_PARAMETER(syscallNumber);
	UNREFERENCED_PARAMETER(func);

	// find the ssdt base 
	// find free space for trampoline 
	// write the trampoline
	// turn off WP in cr0  
	// change the ssdt to the warpper function that will get the elment we sended ... 
	// turn on the WP in cr0
	// enjoy the magic ... 
	PSSDTTable ssdtBase = reinterpret_cast<PSSDTTable>(getssdt1());
	DbgPrint("the actual ssdt is in : %p", ssdtBase->system_service_descriptor_table);
	PVOID freeAddr = findCloseMemory1();
	if (!freeAddr)
		return STATUS_NOT_FOUND;
	
	KIRQL irql = offWPCR0();

	onWPCR0(irql);


	Trampoline tramp(func);
	PUCHAR actualEntry = reinterpret_cast<PUCHAR>(freeAddr) + tramp.prologSize;
	SIZE_T ssdtRVA = reinterpret_cast<PUCHAR>(actualEntry) - reinterpret_cast<PUCHAR>(ssdtBase->system_service_descriptor_table);
	if (ssdtRVA > 0xfffffffu)
		return STATUS_ABANDONED;
	
	NTSTATUS statusTramp = createTrampoline1(freeAddr, &tramp);
	if (!NT_SUCCESS(statusTramp))
		return statusTramp;
		
	SIZE_T originalAddress = ssdtBase->system_service_descriptor_table[syscallNumber];
	SIZE_T offset= originalAddress >> 4 ;  
	PVOID oldFunction = reinterpret_cast<PUCHAR>(ssdtBase->system_service_descriptor_table) + offset; 
	UINT32 resRVA = static_cast<UINT32>(ssdtRVA);
	resRVA = resRVA << 4;
	resRVA |= (originalAddress & 0xF);
	KIRQL irql = offWPCR0();
	memcpy(ssdtBase->system_service_descriptor_table + syscallNumber, &resRVA, sizeof(UINT32));
	onWPCR0(irql);
	PHOOK newHooks = reinterpret_cast<PHOOK>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(HOOK) * ++hookNumber, 'dcba'));
	if (hooks) {
		memcpy(newHooks, hooks, sizeof(HOOK) * (hookNumber - 1));
		ExFreePoolWithTag(hooks, 'dcba');
	}
	newHooks[hookNumber - 1] = HOOK{ syscallNumber,static_cast<UINT32>(originalAddress) };
	hooks = newHooks;
	return 0x0;
}

PVOID getIDTR() {
	return 0x0;
}
PVOID getGDTR() {
	return 0x0;
}
PVOID getSysEnter() {
	return 0x0;
}

PVOID hookIDT() {
	return 0x0;
}

PVOID hookMSR() {
	// just change the msr to yours ...
	// not so complecated - the complcated thig is to parse it 
	/*
		Registers
		MSRs
		These must be accessed through rdmsr and wrmsr
			STAR (0xC0000081) - Ring 0 and Ring 3 Segment bases, as well as SYSCALL EIP.
		Low 32 bits = SYSCALL EIP, bits 32-47 are kernel segment base, bits 48-63 are user segment base.
			LSTAR (0xC0000082) - The kernel's RIP SYSCALL entry for 64 bit software.
			CSTAR (0xC0000083) - The kernel's RIP for SYSCALL in compatibility mode.
			SFMASK (0xC0000084) - The low 32 bits are the SYSCALL flag mask. If a bit in this is set, the corresponding bit in rFLAGS is cleared.
	*/
	return 0x0;
}

PVOID hookIRP() {
	return 0x0;
}

PVOID hookGDT() {
	return 0x0;
}

NTSTATUS inlinHookCall() {
	return 0x0;
}


NTSTATUS hookNotifyRoutine() {
	return 0x0;
}

NTSTATUS removeNotifyRoutine() {
	return 0x0;
}

NTSTATUS inlineHookJMP() {
	return 0x0;
}

NTSTATUS ChangeBGAndFGKiDisplayBlueScreen() {
	/*
	*   KiDisplayBlueScreen
		InbvSolidColorFill(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1, BV_COLOR_BLUE);
		InbvSetTextColor(BV_COLOR_WHITE);
		#define BV_COLOR_BLACK          0
		#define BV_COLOR_RED            1
		#define BV_COLOR_GREEN          2
		#define BV_COLOR_BROWN          3
		#define BV_COLOR_BLUE           4
		#define BV_COLOR_MAGENTA        5
		#define BV_COLOR_CYAN           6
		#define BV_COLOR_DARK_GRAY      7
		#define BV_COLOR_LIGHT_GRAY     8
		#define BV_COLOR_LIGHT_RED      9
		#define BV_COLOR_LIGHT_GREEN    10
		#define BV_COLOR_YELLOW         11
		#define BV_COLOR_LIGHT_BLUE     12
		#define BV_COLOR_LIGHT_MAGENTA  13
		#define BV_COLOR_LIGHT_CYAN     14
		#define BV_COLOR_WHITE          15
		#define BV_COLOR_NONE           16
		#define BV_MAX_COLORS           16
		in the real world and not in reactos the flow is a bit junkier :
		we call to  BgpFwDisplayBugCheckScreen


	*/
	return 0x0;
}

NTSTATUS changeSmilyString(PCWSTR string) {
	UNREFERENCED_PARAMETER(string);
	constexpr UCHAR SMILEY[] = { 0x3A , 0x00 , 0x28 , 0x00 , 0x00 , 0x00 };
	//constexpr UCHAR SMILEME[]{ 0x29 };

	PUCHAR kernelBase = reinterpret_cast<PUCHAR>(GetKernelBase7());
	if (!kernelBase)
		return STATUS_ABANDONED;
	PIMAGE_SECTION_HEADER rdata = getRdataSection(kernelBase);
	if (!rdata)
		return STATUS_ABANDONED;
	SIZE_T offset = find_Offset(kernelBase, rdata->VirtualAddress, rdata->VirtualAddress + rdata->Misc.VirtualSize, const_cast<PUCHAR>(SMILEY), sizeof(SMILEY));
	DbgPrint("the offset is : %x and addr is : %p ", offset, kernelBase + offset);
	PUCHAR myactualAddress = kernelBase + offset;
	SIZE_T myOffset = find_Offset(kernelBase, rdata->VirtualAddress, rdata->VirtualAddress + rdata->Misc.VirtualSize, reinterpret_cast<PUCHAR>(&myactualAddress), sizeof(PVOID));
	DbgPrint("the offset no.2 is : %x and addr no.2 is : %p ", myOffset, kernelBase + myOffset);
	// now we need to search for the struct that saves the  buffer(UNICODE STRING) and to change it to whatewer I like ... 
	;
	// over the len of 2 we are screw realy hard to let's fix that...
	// in the function we draw a rectancle that inside it we draw the string - we will have to make that rectangle bigger - allways ... 

	KIRQL irql = offWPCR0();
	RtlInitUnicodeString(reinterpret_cast<PUNICODE_STRING>(kernelBase + myOffset - sizeof(PVOID)), L";)\x00");
	//memcpy(, &hello, sizeof(PVOID) * 2);
	onWPCR0(irql);



	return STATUS_SUCCESS;
}


NTSTATUS rainBowColorBSOD() {
	// we need to hook the function right after the call to initalize rectangle ... 




	return STATUS_SUCCESS;
}


NTSTATUS hookFileSystemIRP() {
	return 0x0;
}
NTSTATUS hookGDI() {
	return 0x0;
}
constexpr SIZE_T NtOpenFileIndex = 0x33;
// the syscall index number is 0x51 ... 
/*
to get the syscall number from windbg :


.block{
	r? @$t3= *(unsigned int *) @@(nt!KiServiceLimit)
	r? @$t1= (int *) @@(nt!KiServiceTable)
	.for (r? @$t2=0; @$t2 < @$t3 ; r? @$t2=@$t2 + 1) {
		r? @$t4 = @$t1[@$t2] >> 4
		.printf "%d.)",@$t2
		ln @$t4 +@$t1
	}

}

*/
NTSTATUS HOOK_ME_PLZ_OPENFILE(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG ShareAccess, _In_ ULONG OpenOptions) {
	/*
		51.)Browse module
		Set bu breakpoint
		(fffff806`17cb5610)   nt!NtOpenFile   |  (fffff806`17cb5680)   nt!PfVerifyScenarioBuffer
	*/
	DbgPrint("_HOOKME_ open file .:. %wZ ", ObjectAttributes->ObjectName);
	return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}


NTSTATUS restoreSddtEntry(SIZE_T index) {

	UNREFERENCED_PARAMETER(index);

	return STATUS_SUCCESS;
}





void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint(("Sample driver Unload called\n"));
	PSSDTTable ssdtBase = reinterpret_cast<PSSDTTable>(getssdt1());
	DbgPrint("the actual ssdt is in unload is  : %p", ssdtBase->system_service_descriptor_table);
	for (SIZE_T i = 0; i < hookNumber; i++) {
		PHOOK currentHook = hooks + i;
		DbgPrint("Hook %d is in %x and it's RVA is %x", i, currentHook->index, currentHook->RVA);
		KIRQL irql = offWPCR0();
		ssdtBase->system_service_descriptor_table[currentHook->index] = currentHook->RVA;
		onWPCR0(irql);
	}
}

void KillRaspBitmapCache() {}



extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = SampleUnload;
	UNICODE_STRING x;
	x.Buffer = reinterpret_cast<PWCHAR>(ExAllocatePool2(POOL_FLAG_PAGED, RegistryPath->Length, 'dcba')); ;
	if (x.Buffer == nullptr) {
		DbgPrint("cant allocate shit %d", RegistryPath->Length);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	x.MaximumLength = RegistryPath->Length;
	RtlCopyUnicodeString(&x, RegistryPath);
	RTL_OSVERSIONINFOW info = { sizeof(RTL_OSVERSIONINFOW) };
	RtlGetVersion(&info);
	PEPROCESS p = IoGetCurrentProcess();
	auto s1 = (CHAR*)PsGetProcessImageFileName(p);;

	//test 1 
	DbgPrint("Runing from process(Should be System): %s path : %wZ version @build : %d @major: %d @minor: %d ", s1, &x, info.dwBuildNumber, info.dwMajorVersion, info.dwMinorVersion);

	// test 2 
	//DbgPrint("ntoskrnl base 1 : %p \n", GetKernelBase1());
	//DbgPrint("ntoskrnl base 2 : %p \n", GetKernelBase2());
	DbgPrint("ntoskrnl base 3 : %p \n", GetKernelBase3());
	DbgPrint("ntoskrnl base 4 : % p \n", GetKernelBase4(DriverObject));
	DbgPrint("ntoskrnl base 5 : %p\n", GetKernelBase5());
	DbgPrint("ntoskrnl base 6 : %p \n", GetKernelBase6());
	if (NT_SUCCESS(AuxKlibInitialize()))
		DbgPrint("ntoskrnl base 7 : % p \n", GetKernelBase7());

	//test3
	DbgPrint("sddt base 1 : %p", getssdt1());
	DbgPrint("sddt base 2 : %p", getssdt2());

	//test4
	UNICODE_STRING target = RTL_CONSTANT_STRING(L"svchost.exe");
	DbgPrint("EPROCESS of svchost address 1 : %p", getProcessByName1(target));
	
	// fucked up for some reason -> idk!!!
	//DbgPrint("EPROCESS of svchost address 2 : %p", getProcessByName2(target));

	//test5
	DbgPrint("Clear memory for code cave 1 : %p", findCloseMemory1());
	DbgPrint("Clear memory for code cave 2 : %p", findCloseMemory2());





	// test6 
	//DbgPrint("ssdt hook status : %x" ,  hookSSDT(HOOK_ME_PLZ_OPENFILE , NtOpenFileIndex , NULL));

	//test7 
	//changeSmilyString(L";)\x00");
	KIRQL irql = offWPCR0();
	onWPCR0(irql);


	//DbgPrint("Syscall Parse of ZwReadFile : %p", syscallParser("ZwReadFile"));
	return STATUS_SUCCESS;
}
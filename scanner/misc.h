#include <ntifs.h>
#ifndef _MISC_H_
#define _MISC_H_

#ifndef MAX_PATH
#define MAX_PATH 296
#endif

#define PROCESS_QUERY_INFORMATION (0x0400) 
#define INVALID_PID_VALUE 0xFFFFFFFF

typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess;

BOOLEAN NTAPI GetNtDeviceName(WCHAR * filename, WCHAR * ntname);
BOOLEAN NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName);
BOOLEAN IsDosDeviceName(WCHAR * filename);


NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);
BOOLEAN IsShortNamePath(WCHAR * wszFileName);
BOOLEAN ConverShortToLongName(WCHAR *wszLongName, WCHAR *wszShortName, ULONG size);

BOOLEAN IsDir(PIO_STACK_LOCATION pIrpStack);

BOOLEAN IsPatternMatch(PUNICODE_STRING Expression, PUNICODE_STRING Name, BOOLEAN IgnoreCase);
BOOLEAN PatternMatch(WCHAR * pat, WCHAR * str);
BOOLEAN PatternNMatch(WCHAR * pat, WCHAR * str, ULONG count);

#endif
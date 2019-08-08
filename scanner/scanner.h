#pragma once

#include <ntifs.h>
/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

	scrubber.h

Abstract:
	Header file which contains the structures, type definitions,
	constants, global variables and function prototypes that are
	only visible within the kernel.

Environment:

	Kernel mode

--*/
#ifndef __SCANNER_H__
#define __SCANNER_H__


///////////////////////////////////////////////////////////////////////////
//
//  Global variables
//
///////////////////////////////////////////////////////////////////////////


typedef struct _SCANNER_DATA {

	//
	//  The object that identifies this driver.
	//

	PDRIVER_OBJECT DriverObject;

	//
	//  The filter handle that results from a call to
	//  FltRegisterFilter.
	//

	PFLT_FILTER Filter;

	//
	//  Listens for incoming connections
	//

	PFLT_PORT ServerPort;

	//
	//  User process that connected to the port
	//

	PEPROCESS UserProcess;

	//
	//  Client port for a connection to user-mode
	//

	PFLT_PORT ClientPort;


	// Client pid for a connection to user-mode


	ULONG64 ClientPid;

} SCANNER_DATA, *PSCANNER_DATA;

extern SCANNER_DATA ScannerData;



typedef struct _SCANNER_STREAM_HANDLE_CONTEXT {

	BOOLEAN RescanRequired;

} SCANNER_STREAM_HANDLE_CONTEXT, *PSCANNER_STREAM_HANDLE_CONTEXT;

#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

typedef struct _SCANNER_CREATE_PARAMS {

	WCHAR String[0];

} SCANNER_CREATE_PARAMS, *PSCANNER_CREATE_PARAMS;

#pragma warning(pop)

typedef struct {

	ULONG ul_PathLength;
	UNICODE_STRING us_Path;
	LIST_ENTRY list_Entry;

}SCANNER_FILERULE, * PSCANNER_FILERULE;
typedef struct _SCANNER_RECV {

	ULONG option;
	ULONG ul_PathLength;
	wchar_t path[260];

}SCANNER_RECV, * PSCANNER_RECV;

typedef struct
{
	BOOLEAN Result;
	PFILE_OBJECT hFile;
	LIST_ENTRY list_Entry;
}SCANNER_RESULT,*PSCANNER_RESULT;
///////////////////////////////////////////////////////////////////////////
//
//  Prototypes for the startup and unload routines used for 
//  this Filter.
//
//  Implementation in scanner.c
//
///////////////////////////////////////////////////////////////////////////
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
);

NTSTATUS
ScannerUnload(
	__in FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
ScannerQueryTeardown(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

NTSTATUS
ScannerInstanceSetup(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);


FLT_PREOP_CALLBACK_STATUS
ScannerPreSetInformation(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

#endif /* __SCANNER_H__ */


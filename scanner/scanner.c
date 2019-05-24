/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

	scanner.c

Abstract:

	This is the main module of the scanner filter.

	This filter scans the data in a file before allowing an open to proceed.  This is similar
	to what virus checkers do.

Environment:

	Kernel mode

--*/
#define RTL_USE_AVL_TABLES 0
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "..\\inc\\scanuk.h"
#include "scanner.h"
#include "misc.h"

#include <ntddk.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
FAST_MUTEX sFunmutex1;
FAST_MUTEX sFunmutex2;
//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//
RTL_AVL_TABLE g_avl_table;
SCANNER_DATA ScannerData;

//
//  This is a static list of file name extensions files we are interested in scanning
//
typedef struct _AV_GENERIC_TABLE_ENTRY {

	HANDLE hFile;  //文件句柄
	ULONG dw_Pid;   //进程PID
	ULONG option;   //打开的方式
	WCHAR ProcessPath[MAX_PATH]; //进程路径
	WCHAR FilePath[MAX_PATH];    //文件路径       
	BOOLEAN IsOpen; //保存结果
} AV_GENERIC_TABLE_ENTRY, *PAV_GENERIC_TABLE_ENTRY;


const UNICODE_STRING ScannerExtensionsToScan[] =
{ RTL_CONSTANT_STRING(L"doc"),
  RTL_CONSTANT_STRING(L"txt"),
  RTL_CONSTANT_STRING(L"bat"),
  RTL_CONSTANT_STRING(L"cmd"),
  RTL_CONSTANT_STRING(L"inf"),
	/*RTL_CONSTANT_STRING( L"ini"),   Removed, to much usage*/
	{0, 0, NULL}
};


//
//  Function prototypes
//

NTSTATUS
ScannerPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
);

VOID
ScannerPortDisconnect(
	__in_opt PVOID ConnectionCookie
);

NTSTATUS
ScannerpScanFileInUserMode(
	__in PFLT_INSTANCE Instance,
	__in PFILE_OBJECT FileObject,
	__out PBOOLEAN SafeToOpen
);
NTSTATUS
ScannerpSendMessageInUserMode(
	__in PFLT_INSTANCE Instance,
	__in AV_GENERIC_TABLE_ENTRY entry,	
	__out PBOOLEAN SafeToOpen
);
BOOLEAN
ScannerpCheckExtension(
	__in PUNICODE_STRING Extension
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ScannerInstanceSetup)
#pragma alloc_text(PAGE, ScannerPreCreate)
#pragma alloc_text(PAGE, ScannerPortConnect)
#pragma alloc_text(PAGE, ScannerPortDisconnect)
#endif


//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

const FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	  0,
	  ScannerPreCreate,
	  ScannerPostCreate},

	{ IRP_MJ_CLEANUP,
	  0,
	  ScannerPreCleanup,
	  NULL},

	{ IRP_MJ_WRITE,
	  0,
	  ScannerPreWrite,
	  NULL},

	{ IRP_MJ_OPERATION_END}
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	  0,
	  NULL,
	  sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
	  'chBS' },

	{ FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	ContextRegistration,                //  Context Registration.
	Callbacks,                          //  Operation callbacks
	ScannerUnload,                      //  FilterUnload
	ScannerInstanceSetup,               //  InstanceSetup
	ScannerQueryTeardown,               //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

//二叉树回调函数


RTL_GENERIC_COMPARE_RESULTS
NTAPI
AvCompareEntry(
	_In_ PRTL_AVL_TABLE Table,
	_In_ PVOID Lhs,
	_In_ PVOID Rhs
)
/*++

Routine Description:

	This routine is the callback for the generic table routines.

Arguments:

	Table       - Table for which this is invoked.

	FirstStruct - An element in the table to compare.

	SecondStruct - Another element in the table to compare.

Return Value:

	RTL_GENERIC_COMPARE_RESULTS.

--*/
{
	PAV_GENERIC_TABLE_ENTRY lhs = (PAV_GENERIC_TABLE_ENTRY)Lhs;
	PAV_GENERIC_TABLE_ENTRY rhs = (PAV_GENERIC_TABLE_ENTRY)Rhs;

	UNREFERENCED_PARAMETER(Table);

	//
	//  Compare the 128 bit fileId in 64bit pieces for efficiency.
	//  Compare the lower 64 bits Value first since that is used
	//  in both 128 bit and 64 bit fileIds and doing so eliminates
	//  and unnecessary comparison of the UpperZeros field in the
	//  most common case. Note this comparison is not equivalent
	//  to a memcmp on the 128 bit values but that doesn't matter
	//  here since we just need the tree to be self-consistent.
	//

	if (lhs->dw_Pid < rhs->dw_Pid) {

		return GenericLessThan;

	}
	else if (lhs->dw_Pid > rhs->dw_Pid) {

		return GenericGreaterThan;

	}
    else if (lhs->option < rhs->option) {

        return GenericLessThan;

    }
    else if (lhs->option > rhs->option) {

        return GenericGreaterThan;
    }
	else if ((int)lhs->hFile > (int)rhs->hFile)
	{
		return GenericGreaterThan;
	}
	else if ((int)lhs->hFile < (int)rhs->hFile)
	{
		return GenericLessThan;
	}
	return GenericEqual;
}

PVOID
NTAPI
AvAllocateGenericTableEntry(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ CLONG ByteSize
)
/*++

Routine Description:

	This routine is the callback for allocation for entries in the generic table.

Arguments:

	Table       - Table for which this is invoked.

	ByteSize    - Amount of memory to allocate.

Return Value:

	Pointer to allocated memory if successful, else NULL.

--*/
{

	UNREFERENCED_PARAMETER(Table);

	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'lwla');
}

VOID
NTAPI
AvFreeGenericTableEntry(
	_In_ PRTL_GENERIC_TABLE Table,
	_In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Entry
)
/*++

Routine Description:

	This routine is the callback for releasing memory for entries in the generic
	table.

Arguments:

	Table       - Table for which this is invoked.

	Entry       - Entry to free.

Return Value:

	None.

--*/
{

	UNREFERENCED_PARAMETER(Table);

	ExFreePoolWithTag(Entry, 'lwla');
}


////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for the Filter driver.  This
	registers the Filter with the filter manager and initializes all
	its global data structures.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Returns STATUS_SUCCESS.
--*/
{
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);
	ExInitializeFastMutex(&sFunmutex1);
	ExInitializeFastMutex(&sFunmutex2);
    RtlInitializeGenericTableAvl(&g_avl_table, AvCompareEntry, AvAllocateGenericTableEntry, AvFreeGenericTableEntry, NULL);
	//
	//  Register with filter manager.
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&ScannerData.Filter);


	if (!NT_SUCCESS(status)) {

		return status;
	}

	//
	//  Create a communication port.
	//

	RtlInitUnicodeString(&uniString, ScannerPortName);

	//
	//  We secure the port so only ADMINs & SYSTEM can acecss it.
	//

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status)) {

		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);

		status = FltCreateCommunicationPort(ScannerData.Filter,
			&ScannerData.ServerPort,
			&oa,
			NULL,
			ScannerPortConnect,
			ScannerPortDisconnect,
			NULL,//作业，补充
			1);
		//
		//  Free the security descriptor in all cases. It is not needed once
		//  the call to FltCreateCommunicationPort() is made.
		//

		FltFreeSecurityDescriptor(sd);

		if (NT_SUCCESS(status)) {

			//
			//  Start filtering I/O.
			//

			status = FltStartFiltering(ScannerData.Filter);

			if (NT_SUCCESS(status)) {

				return STATUS_SUCCESS;
			}

			FltCloseCommunicationPort(ScannerData.ServerPort);
		}
	}

	FltUnregisterFilter(ScannerData.Filter);

	return status;
}


NTSTATUS
ScannerPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
)
/*++

Routine Description

	This is called when user-mode connects to the server port - to establish a
	connection

Arguments

	ClientPort - This is the client connection port that will be used to
		send messages from the filter

	ServerPortCookie - The context associated with this port when the
		minifilter created this port.

	ConnectionContext - Context from entity connecting to this port (most likely
		your user mode service)

	SizeofContext - Size of ConnectionContext in bytes

	ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

	STATUS_SUCCESS - to accept the connection

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ASSERT(ScannerData.ClientPort == NULL);
	ASSERT(ScannerData.UserProcess == NULL);

	//
	//  Set the user process and port.
	//

	ScannerData.UserProcess = PsGetCurrentProcess();
	ScannerData.ClientPort = ClientPort;
	ScannerData.ClientPid = (ULONG)PsGetCurrentProcessId();
	DbgPrint("!!! scanner.sys --- connected, port=0x%p  PID=%d\n ", ClientPort, ScannerData.ClientPid);

	return STATUS_SUCCESS;
}

VOID
ScannerPortDisconnect(
	__in_opt PVOID ConnectionCookie
)
/*++

Routine Description

	This is called when the connection is torn-down. We use it to close our
	handle to the connection

Arguments

	ConnectionCookie - Context from the port connect routine

Return value

	None

--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("!!! scanner.sys --- disconnected, port=0x%p\n", ScannerData.ClientPort);

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort(ScannerData.Filter, &ScannerData.ClientPort);

	//
	//  Reset the user-process field.
	//

	ScannerData.UserProcess = NULL;
}

NTSTATUS
ScannerUnload(
	__in FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

	This is the unload routine for the Filter driver.  This unregisters the
	Filter with the filter manager and frees any allocated global data
	structures.

Arguments:

	None.

Return Value:

	Returns the final status of the deallocation routines.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	//
	//  Close the server port.
	//

	FltCloseCommunicationPort(ScannerData.ServerPort);

	//
	//  Unregister the filter
	//

	FltUnregisterFilter(ScannerData.Filter);

	return STATUS_SUCCESS;
}

NTSTATUS
ScannerInstanceSetup(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

	This routine is called by the filter manager when a new instance is created.
	We specified in the registry that we only want for manual attachments,
	so that is all we should receive here.

Arguments:

	FltObjects - Describes the instance and volume which we are being asked to
		setup.

	Flags - Flags describing the type of attachment this is.

	VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
		will attach.

	VolumeFileSystemType - The file system formatted on this volume.

Return Value:

  FLT_NOTIFY_STATUS_ATTACH              - we wish to attach to the volume
  FLT_NOTIFY_STATUS_DO_NOT_ATTACH       - no, thank you

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	ASSERT(FltObjects->Filter == ScannerData.Filter);

	//
	//  Don't attach to network volumes.
	//

	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
ScannerQueryTeardown(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This is the instance detach routine for the filter. This
	routine is called by filter manager when a user initiates a manual instance
	detach. This is a 'query' routine: if the filter does not want to support
	manual detach, it can return a failure status

Arguments:

	FltObjects - Describes the instance and volume for which we are receiving
		this query teardown request.

	Flags - Unused

Return Value:

	STATUS_SUCCESS - we allow instance detach to happen

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

	Pre create callback.  We need to remember whether this file has been
	opened for write access.  If it has, we'll want to rescan it in cleanup.
	This scheme results in extra scans in at least two cases:
	-- if the create fails (perhaps for access denied)
	-- the file is opened for write access but never actually written to
	The assumption is that writes are more common than creates, and checking
	or setting the context in the write path would be less efficient than
	taking a good guess before the create.

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - Output parameter which can be used to pass a context
		from this pre-create callback to the post-create callback.

Return Value:

   FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
   FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	//
	//  See if this create is being done by our user process.
	//

	if (IoThreadToProcess(Data->Thread) == ScannerData.UserProcess) {

		DbgPrint("!!! scanner.sys -- allowing create for trusted process \n");

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

BOOLEAN
ScannerpCheckExtension(
	__in PUNICODE_STRING Extension
)
/*++

Routine Description:

	Checks if this file name extension is something we are interested in

Arguments

	Extension - Pointer to the file name extension

Return Value

	TRUE - Yes we are interested
	FALSE - No
--*/
{
	const UNICODE_STRING *ext;

	if (Extension->Length == 0) {

		return FALSE;
	}

	//
	//  Check if it matches any one of our static extension list
	//

	ext = ScannerExtensionsToScan;

	while (ext->Buffer != NULL) {

		if (RtlCompareUnicodeString(Extension, ext, TRUE) == 0) {

			//
			//  A match. We are interested in this file
			//

			return TRUE;
		}
		ext++;
	}

	return FALSE;
}


FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	Post create callback.  We can't scan the file until after the create has
	gone to the filesystem, since otherwise the filesystem wouldn't be ready
	to read the file for us.

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - The operation context passed fron the pre-create
		callback.

	Flags - Flags to say why we are getting this post-operation callback.

Return Value:

	FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
									 access to this file, hence undo the open

--*/
{
	PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
	FLT_POSTOP_CALLBACK_STATUS returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	BOOLEAN safeToOpen, scanFile,PopWindow;
	ULONG ulOption = Data->Iopb->Parameters.Create.Options;
	FILE_DISPOSITION_INFORMATION  fdi;
	ULONG ulDisposition;
    AV_GENERIC_TABLE_ENTRY entry = { 0 };
	PopWindow = FALSE;
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	
	//
	//  If this create was failing anyway, don't bother scanning now.
	//

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//检测放行行为
	if (Data->RequestorMode == KernelMode || FltGetRequestorProcessId(Data) == ScannerData.ClientPid || FlagOn(ulOption, FILE_DIRECTORY_FILE) ||
		FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) || FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
		FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) || FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO)
		)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//  Check if we are interested in this file.
	//
	//在这里判断我们需要弹窗的操作
	//这里是在判断如果是创建操作的操作,我们就需要弹窗，允许不允许它弹窗
	ulDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
	if (ulDisposition == FILE_CREATE || ulDisposition == FILE_OVERWRITE || ulDisposition == FILE_OVERWRITE_IF)
	{
		PopWindow = TRUE;
	}



	status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo);

	if (!NT_SUCCESS(status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FltParseFileNameInformation(nameInfo);

	//
	//  Check if the extension matches the list of extensions we are interested in
	//


	scanFile = ScannerpCheckExtension(&nameInfo->Extension);
    
    
	//
	//  Release file name info, we're done with it
	//

	

	if (!scanFile) {

		//
		//  Not an extension we are interested in
		//

		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	//这里如果是创建操作就要弹窗，允许不允许创建，如果允许创建了，就不需要在扫描文件的文件流，等它关闭的时候
	//进行数据流的判断，或者对它的MD5，甚至加解密操作。

	//需要判断如果是创建操作，就不进行打开文件，扫描。如果不是创建操作，就进行MD5等查询方法，判断是它是不是一个有问题的文件。
		//创建打开文件，重命名文件都有的操作
		//获取进程的路径，
	UNICODE_STRING us_ProcessPath = { 0 };
	us_ProcessPath.Buffer = entry.ProcessPath;
	us_ProcessPath.MaximumLength = sizeof(entry.ProcessPath);
	GetProcessFullNameByPid(PsGetCurrentProcessId(), &us_ProcessPath);
	DbgPrint("Process Path: %ws \n", entry.ProcessPath);
	//获取文件的名称
	
	wcsncpy(entry.FilePath, nameInfo->Name.Buffer,MAX_PATH);
	DbgPrint("File Path:%ws \n", entry.FilePath);
	FltReleaseFileNameInformation(nameInfo);
	if (PopWindow)
	{
		//需要弹窗就是创建操作,1为创建操作
		(VOID)ScannerpSendMessageInUserMode(FltObjects->Instance,entry,&safeToOpen);
		safeToOpen = TRUE;
	}
	else
	{
		//否则，在这里就是在正常的判断是不是需要打开的操作
		(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
			FltObjects->FileObject,
			&safeToOpen);
	}
	if (!safeToOpen) {

		//
		//  Ask the filter manager to undo the create.
		//

		DbgPrint("!!! scanner.sys -- foul language detected in postcreate !!!\n");		

		//如果是创建操作，我们拒绝了这个创建的操作，还需要删除这个空的文件，否则扫描文件的话，只需要对它进行拒绝访问操作
		if (PopWindow)
		{
			DbgPrint("!!! scanner.sys -- undoing create \n");
			fdi.DeleteFile = TRUE;
			FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &fdi, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
		}
		FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;

		returnStatus = FLT_POSTOP_FINISHED_PROCESSING;

	}
	//这里是允许创建和打开以后，有写的权限的时候就需要对它设置上下文，进行文件流的扫描。
	else if (FltObjects->FileObject->WriteAccess) {

		//
		//
		//  The create has requested write access, mark to rescan the file.
		//  Allocate the context.
		//

		status = FltAllocateContext(ScannerData.Filter,
			FLT_STREAMHANDLE_CONTEXT,//file_object
			sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
			PagedPool,
			&scannerContext);

		if (NT_SUCCESS(status)) {

			//
			//  Set the handle context.
			//

			scannerContext->RescanRequired = TRUE;

			(VOID)FltSetStreamHandleContext(FltObjects->Instance,
				FltObjects->FileObject,
				FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
				scannerContext,
				NULL);

			//
			//  Normally we would check the results of FltSetStreamHandleContext
			//  for a variety of error cases. However, The only error status 
			//  that could be returned, in this case, would tell us that
			//  contexts are not supported.  Even if we got this error,
			//  we just want to release the context now and that will free
			//  this memory if it was not successfully set.
			//

			//
			//  Release our reference on the context (the set adds a reference)
			//

			FltReleaseContext(scannerContext);
		}
	}

	return returnStatus;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

	Pre cleanup callback.  If this file was opened for write access, we want
	to rescan it now.

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - Output parameter which can be used to pass a context
		from this pre-cleanup callback to the post-cleanup callback.

Return Value:

	Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
	NTSTATUS status;
	PSCANNER_STREAM_HANDLE_CONTEXT context;
	BOOLEAN safe;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	if (NT_SUCCESS(status)) {

		if (context->RescanRequired) {//写关闭

			(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
				FltObjects->FileObject,
				&safe);

			if (!safe) {

				DbgPrint("!!! scanner.sys -- foul language detected in precleanup !!!\n");
			}
		}

		FltReleaseContext(context);
	}


	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

	Pre write callback.  We want to scan what's being written now.

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - Output parameter which can be used to pass a context
		from this pre-write callback to the post-write callback.

Return Value:

	Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS status;
	PSCANNER_NOTIFICATION notification = NULL;
	PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
	ULONG replyLength;
	BOOLEAN safe = TRUE;
	PUCHAR buffer;

	UNREFERENCED_PARAMETER(CompletionContext);

	//
	//  If not client port just ignore this write.
	//

	if (ScannerData.ClientPort == NULL) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	if (!NT_SUCCESS(status)) {

		//
		//  We are not interested in this file
		//

		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	}

	//
	//  Use try-finally to cleanup
	//

	try {

		//
		//  Pass the contents of the buffer to user mode.
		//

		if (Data->Iopb->Parameters.Write.Length != 0) {

			//
			//  Get the users buffer address.  If there is a MDL defined, use
			//  it.  If not use the given buffer address.
			//

			if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {

				buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
					NormalPagePriority);

				//
				//  If we have a MDL but could not get and address, we ran out
				//  of memory, report the correct error
				//

				if (buffer == NULL) {

					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
					returnStatus = FLT_PREOP_COMPLETE;
					leave;
				}

			}
			else {

				//
				//  Use the users buffer
				//

				buffer = Data->Iopb->Parameters.Write.WriteBuffer;
			}

			//
			//  In a production-level filter, we would actually let user mode scan the file directly.
			//  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
			//  This is just a sample!
			//

			notification = ExAllocatePoolWithTag(NonPagedPool,
				sizeof(SCANNER_NOTIFICATION),
				'nacS');
			if (notification == NULL) {

				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			notification->BytesToScan = min(Data->Iopb->Parameters.Write.Length, SCANNER_READ_BUFFER_SIZE);

			//
			//  The buffer can be a raw user buffer. Protect access to it
			//

			try {

				RtlCopyMemory(&notification->Contents,
					buffer,
					notification->BytesToScan);

			} except(EXCEPTION_EXECUTE_HANDLER) {

				//
				//  Error accessing buffer. Complete i/o with failure
				//

				Data->IoStatus.Status = GetExceptionCode();
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			//
			//  Send message to user mode to indicate it should scan the buffer.
			//  We don't have to synchronize between the send and close of the handle
			//  as FltSendMessage takes care of that.
			//

			replyLength = sizeof(SCANNER_REPLY);

			status = FltSendMessage(ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,
				sizeof(SCANNER_NOTIFICATION),
				notification,
				&replyLength,
				NULL);

			if (STATUS_SUCCESS == status) {

				safe = ((PSCANNER_REPLY)notification)->SafeToOpen;

			}
			else {

				//
				//  Couldn't send message. This sample will let the i/o through.
				//

				DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
		}

		if (!safe) {

			//
			//  Block this write if not paging i/o (as a result of course, this scanner will not prevent memory mapped writes of contaminated
			//  strings to the file, but only regular writes). The effect of getting ERROR_ACCESS_DENIED for many apps to delete the file they
			//  are trying to write usually.
			//  To handle memory mapped writes - we should be scanning at close time (which is when we can really establish that the file object
			//  is not going to be used for any more writes)
			//

			DbgPrint("!!! scanner.sys -- foul language detected in write !!!\n");

			if (!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {

				DbgPrint("!!! scanner.sys -- blocking the write !!!\n");

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
			}
		}

	}
	finally{

	 if (notification != NULL) {

		 ExFreePoolWithTag(notification, 'nacS');
	 }

	 if (context) {

		 FltReleaseContext(context);
	 }
	}

	return returnStatus;
}

//////////////////////////////////////////////////////////////////////////
//  Local support routines.
//
/////////////////////////////////////////////////////////////////////////

NTSTATUS
ScannerpScanFileInUserMode(
	__in PFLT_INSTANCE Instance,
	__in PFILE_OBJECT FileObject,
	__out PBOOLEAN SafeToOpen
)
/*++

Routine Description:

	This routine is called to send a request up to user mode to scan a given
	file and tell our caller whether it's safe to open this file.

	Note that if the scan fails, we set SafeToOpen to TRUE.  The scan may fail
	because the service hasn't started, or perhaps because this create/cleanup
	is for a directory, and there's no data to read & scan.

	If we failed creates when the service isn't running, there'd be a
	bootstrapping problem -- how would we ever load the .exe for the service?

Arguments:

	Instance - Handle to the filter instance for the scanner on this volume.

	FileObject - File to be scanned.

	SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
				 foul language.

Return Value:

	The status of the operation, hopefully STATUS_SUCCESS.  The common failure
	status will probably be STATUS_INSUFFICIENT_RESOURCES.

--*/

{
	ExAcquireFastMutex(&sFunmutex1);
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = NULL;
	ULONG bytesRead;
	PSCANNER_NOTIFICATION notification = NULL;
	FLT_VOLUME_PROPERTIES volumeProps;
	LARGE_INTEGER offset;
	ULONG replyLength, length;
	PFLT_VOLUME volume = NULL;

	*SafeToOpen = TRUE;

	//
	//  If not client port just return.
	//

	if (ScannerData.ClientPort == NULL) {

		return STATUS_SUCCESS;
	}

	try {

		//
		//  Obtain the volume object .
		//

		status = FltGetVolumeFromInstance(Instance, &volume);

		if (!NT_SUCCESS(status)) {

			leave;
		}

		//
		//  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
		//  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
		//  instance setup routine and setup an instance context where we can cache it.
		//

		status = FltGetVolumeProperties(volume,
			&volumeProps,
			sizeof(volumeProps),
			&length);
		//
		//  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
		//  hence we only check for error status.
		//

		if (NT_ERROR(status)) {

			leave;
		}

		length = max(SCANNER_READ_BUFFER_SIZE, volumeProps.SectorSize);

		//
		//  Use non-buffered i/o, so allocate aligned pool
		//

		buffer = FltAllocatePoolAlignedWithTag(Instance,
			NonPagedPool,
			length,
			'nacS');

		if (NULL == buffer) {

			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		notification = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(SCANNER_NOTIFICATION),
			'nacS');

		if (NULL == notification) {

			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		//
		//  Read the beginning of the file and pass the contents to user mode.
		//

		offset.QuadPart = bytesRead = 0;
		status = FltReadFile(Instance,
			FileObject,
			&offset,
			length,
			buffer,
			FLTFL_IO_OPERATION_NON_CACHED |
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&bytesRead,
			NULL,
			NULL);

		if (NT_SUCCESS(status) && (0 != bytesRead)) {

			notification->BytesToScan = (ULONG)bytesRead;

			//
			//  Copy only as much as the buffer can hold
			//

			RtlCopyMemory(&notification->Contents,
				buffer,
				min(notification->BytesToScan, SCANNER_READ_BUFFER_SIZE));

			replyLength = sizeof(SCANNER_REPLY);

			status = FltSendMessage(ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,//request
				sizeof(SCANNER_NOTIFICATION),
				notification,//reply
				&replyLength,
				NULL);

			if (STATUS_SUCCESS == status) {

				*SafeToOpen = ((PSCANNER_REPLY)notification)->SafeToOpen;

			}
			else {

				//
				//  Couldn't send message
				//

				DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
		}

	}
	finally{

	 if (NULL != buffer) {

		 FltFreePoolAlignedWithTag(Instance, buffer, 'nacS');
	 }

	 if (NULL != notification) {

		 ExFreePoolWithTag(notification, 'nacS');
	 }

	 if (NULL != volume) {

		 FltObjectDereference(volume);
	 }
	}
	ExReleaseFastMutex(&sFunmutex1);
	return status;
}
#pragma warning(push)
#pragma warning(disable:4100)
#pragma warning(disable:4101)
NTSTATUS
ScannerpSendMessageInUserMode(
	__in PFLT_INSTANCE Instance,
	__in AV_GENERIC_TABLE_ENTRY entry,
	__out PBOOLEAN SafeToOpen
){
	ExAcquireFastMutex(&sFunmutex2);
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = NULL;
	ULONG bytesRead;
	PSCANNER_NOTIFICATION notification = NULL;
	
	LARGE_INTEGER offset;
	ULONG replyLength, length;
	
	*SafeToOpen = TRUE;

	//
	//  If not client port just return.
	//

	if (ScannerData.ClientPort == NULL) {

		return STATUS_SUCCESS;
	}
	PAGED_CODE();
	
	try {

		//申请需要发送的结构体
		notification = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(PSCANNER_NOTIFICATION),
			'nacS');

		if (NULL == notification) {

			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}
		//填写这个结构体
		switch (entry.option)
		{
		case 2:
		{

			break;
		}
		case 3:
		{
			break;
		}
		default:			
			break; 
		}
		//
		//  Read the beginning of the file and pass the contents to user mode.
		//
		notification->Option = 1;
		wcscpy_s(notification->ProcessPath, MAX_PATH, entry.ProcessPath );
		wcscpy_s(notification->FilePath, MAX_PATH, entry.FilePath);
		status = FltSendMessage(ScannerData.Filter,
			&ScannerData.ClientPort,
			notification,//request
			sizeof(SCANNER_NOTIFICATION),
			notification,//reply
			&replyLength,
			NULL);

		if (STATUS_SUCCESS == status) {

			*SafeToOpen = ((PSCANNER_REPLY)notification)->SafeToOpen;

		}
		else {

			//
			//  Couldn't send message
			//

			DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
		}


	}
	finally{

	 if (NULL != buffer) {

		 FltFreePoolAlignedWithTag(Instance, buffer, 'nacS');
	 }

	 if (NULL != notification) {

		 ExFreePoolWithTag(notification, 'nacS');
	 }
	 
	}
	ExReleaseFastMutex(&sFunmutex2);
	return status;
	
};
#pragma warning(pop)
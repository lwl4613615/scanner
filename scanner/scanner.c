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

//×ÔÐýËø
KSPIN_LOCK g_lock;
LIST_ENTRY g_RuleList;
LIST_ENTRY g_ResultList;
ERESOURCE g_Eresource;
NTKERNELAPI
UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);
//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

SCANNER_DATA ScannerData;

//
//  This is a static list of file name extensions files we are interested in scanning
//
typedef struct _AV_GENERIC_TABLE_ENTRY {

	HANDLE hFile;  //ÎÄ¼þ¾ä±ú
	ULONG dw_Pid;   //½ø³ÌPID
	ULONG option;   //´ò¿ªµÄ·½Ê½
	WCHAR ProcessPath[MAX_PATH]; //½ø³ÌÂ·¾¶
	WCHAR FilePath[MAX_PATH];    //ÎÄ¼þÂ·¾¶     
	WCHAR RenamePath[MAX_PATH];
	BOOLEAN IsOpen; //±£´æ½á¹û
} AV_GENERIC_TABLE_ENTRY, *PAV_GENERIC_TABLE_ENTRY;


const UNICODE_STRING ScannerExtensionsToScan[] =
{ RTL_CONSTANT_STRING(L"doc"),
  RTL_CONSTANT_STRING(L"txt"),
  RTL_CONSTANT_STRING(L"bat"),
  RTL_CONSTANT_STRING(L"cmd"),
  RTL_CONSTANT_STRING(L"inf"),
  RTL_CONSTANT_STRING(L"sys"),
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
	__in PAV_GENERIC_TABLE_ENTRY entry,
	__out PBOOLEAN SafeToOpen
);

NTSTATUS
ScannerPortR3toR0(
	IN PVOID PortCookie,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength
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
	{
	IRP_MJ_SET_INFORMATION,
	0,
	ScannerPreSetInformation,
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

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////
BOOLEAN IsMyFilterPath(UNICODE_STRING PatH)
{
	LIST_ENTRY* p = NULL;
	
	for (p=g_RuleList.Flink;p!=&g_RuleList;p=p->Flink)
	{		
		PSCANNER_FILERULE my_node= CONTAINING_RECORD(p, SCANNER_FILERULE, list_Entry);	
		if (PatternMatch(my_node->us_Path.Buffer, PatH.Buffer))
		{
			
			return TRUE;
		}

	}
	
	return FALSE;
}
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
	ExInitializeResourceLite(&g_Eresource);

	KeInitializeSpinLock(&g_lock);
	DbgBreakPoint();
	//初始化双向链表头部
	InitializeListHead(&g_RuleList);
	InitializeListHead(&g_ResultList);
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
			ScannerPortR3toR0,//×÷Òµ£¬²¹³ä
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
	ScannerData.ClientPid = (ULONG64)PsGetCurrentProcessId();
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

NTSTATUS InsertResultList(BOOLEAN Result,PFILE_OBJECT hFile)
{
	PSCANNER_RESULT my_FileResult = (PSCANNER_RESULT)ExAllocatePoolWithTag(
		NonPagedPool, sizeof(SCANNER_RESULT), 'lwlz');
	if (NULL == my_FileResult)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	my_FileResult->Result = Result;
	my_FileResult->hFile = hFile;
	ExAcquireResourceExclusiveLite(&g_Eresource, TRUE);
	InsertHeadList(&g_ResultList, (PLIST_ENTRY)& my_FileResult->list_Entry);
	ExReleaseResourceLite(&g_Eresource);
	return STATUS_SUCCESS;

}
BOOLEAN SearchResultList(PFILE_OBJECT hFile, BOOLEAN* Result)
{
	LIST_ENTRY* p = NULL;
	for (p = g_ResultList.Flink; p != &g_ResultList; p = p->Flink)
	{
		PSCANNER_RESULT my_node = CONTAINING_RECORD(p, SCANNER_RESULT, list_Entry);
		if (my_node->hFile==hFile)
		{
			*Result = my_node->Result;
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN RemoveResultList(PFILE_OBJECT hFile)
{
	LIST_ENTRY* p = NULL;
	for (p = g_ResultList.Flink; p != &g_ResultList; p = p->Flink)
	{
		PSCANNER_RESULT my_node = CONTAINING_RECORD(p, SCANNER_RESULT, list_Entry);
		if (my_node->hFile==hFile)
		{
			ExAcquireResourceExclusiveLite(&g_Eresource, TRUE);
			BOOLEAN result = RemoveEntryList(p);
			ExReleaseResourceLite(&g_Eresource);			
			ExFreePool(my_node);
			return result;
		}

	}
	return FALSE;
}

NTSTATUS InsertRuleList(ULONG Size, UNICODE_STRING Path)
{
	PSCANNER_FILERULE my_FileRule = (PSCANNER_FILERULE)ExAllocatePoolWithTag(
		NonPagedPool, sizeof(SCANNER_FILERULE), 'lwlz');
	if (NULL == my_FileRule)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	my_FileRule->ul_PathLength = Size;
	my_FileRule->us_Path = Path;
	ExAcquireResourceExclusiveLite(&g_Eresource,TRUE);
	InsertHeadList(&g_RuleList, (PLIST_ENTRY)&my_FileRule->list_Entry);
	ExReleaseResourceLite(&g_Eresource);
	return STATUS_SUCCESS;
	
};

BOOLEAN RemoveRuleList(UNICODE_STRING Path)
{
    LIST_ENTRY* p = NULL;
    for (p = g_RuleList.Flink; p != &g_RuleList; p = p->Flink)
    {
        PSCANNER_FILERULE my_node = CONTAINING_RECORD(p, SCANNER_FILERULE, list_Entry);
        if (!wcscmp(my_node->us_Path.Buffer,Path.Buffer))
        {
           
            ExAcquireResourceExclusiveLite(&g_Eresource, TRUE);
            BOOLEAN result = RemoveEntryList(p);
            ExReleaseResourceLite(&g_Eresource);
            ExFreePool(my_node->us_Path.Buffer);
            ExFreePool(my_node);
            DbgPrint("RemoveList Success \n");
            return result;
        }

    }
    return FALSE;
}

NTSTATUS ScannerPortR3toR0(IN PVOID PortCookie,
	IN PVOID InputBuffer OPTIONAL, 
	IN ULONG InputBufferLength, 
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength, 
	OUT PULONG ReturnOutputBufferLength)
{
	NTSTATUS status=STATUS_SUCCESS;

	PAGED_CODE();
	
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
	DbgPrint("[mini-filter] R3toR0Message");

	if ((InputBuffer != NULL)&&((PSCANNER_RECV)InputBuffer)->ul_PathLength<=260&&InputBufferLength==sizeof(SCANNER_RECV)) {

 		try {
// 			//  Probe and capture input message: the message is raw user mode
// 			//  buffer, so need to protect with exception handler
		ProbeForRead(InputBuffer, InputBufferLength, sizeof(ULONG));//地址合法性校验

		ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(ULONG));//地址合法性校验
// 
		} except(EXCEPTION_EXECUTE_HANDLER) {

			return GetExceptionCode();
		}
		PSCANNER_RECV temp = (PSCANNER_RECV)InputBuffer;
		ULONG Path_size = temp->ul_PathLength + 1;
		DbgPrint("path_size %d\n", Path_size);
		UNICODE_STRING un_Path = {0};
		un_Path.Length = (USHORT)(Path_size) * sizeof(wchar_t);
		un_Path.MaximumLength = (USHORT)260 * sizeof(wchar_t);
        //这里申请的内存会移除链表操作那里进行释放。

		un_Path.Buffer = ExAllocatePoolWithTag(PagedPool, 260 * sizeof(WCHAR), 'POCU');
		//进行字符串的拷贝操作
		wcsncpy(un_Path.Buffer, temp->path, Path_size);
		DbgPrint("rev:%ws \n", un_Path.Buffer);
		if (un_Path.Buffer==NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		switch (temp->option)
		{
		case 1:
			//如果是1就进行插入操作
			InsertRuleList(Path_size, un_Path);
			break;			
		case 2:
			//如果是2就进行释放操作
            RemoveRuleList(un_Path);
			break;
		default:
			break;
		}	
		

		
		//ExFreePool(un_Path.Buffer);
		return status;
	}
	return status;
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
	ExDeleteResourceLite(&g_Eresource);
	FltCloseCommunicationPort(ScannerData.ServerPort);

	//
	//  Unregister the filter
	//
	
	FltUnregisterFilter(ScannerData.Filter);
	while (!IsListEmpty(&g_RuleList))
	{
		//从尾部删除一个元素
		PLIST_ENTRY pEntry = RemoveTailList(&g_RuleList); //返回删除结构中ListEntry的位置
		PSCANNER_FILERULE pData = CONTAINING_RECORD(pEntry,
			SCANNER_FILERULE,
			list_Entry);
		KdPrint(("ExFree list:%ws \n", pData->us_Path));
		ExFreePool(pData->us_Path.Buffer);
		ExFreePool(pData);
	}
	while (!IsListEmpty(&g_ResultList))
	{
		//从尾部删除一个元素
		PLIST_ENTRY pEntry = RemoveTailList(&g_ResultList); //返回删除结构中ListEntry的位置
		PSCANNER_RESULT pData = CONTAINING_RECORD(pEntry,
			SCANNER_RESULT,
			list_Entry);		
		ExFreePool(pData);
	}
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

	//´´½¨µÄÀàÐÍ
	NTSTATUS status;
	BOOLEAN PopWindow = FALSE;
	ULONG ulDisposition = 0;
	ULONG ulOption = Data->Iopb->Parameters.Create.Options;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	
	BOOLEAN safeToOpen = TRUE, scanFile = FALSE;
	FILE_DISPOSITION_INFORMATION  fdi;
	PAGED_CODE();
	AV_GENERIC_TABLE_ENTRY entry = { 0 };
	//
	//  See if this create is being done by our user process.
	//

	if (IoThreadToProcess(Data->Thread) == ScannerData.UserProcess) {

		//DbgPrint("!!! scanner.sys -- allowing create for trusted process \n");

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	//¼ì²â·ÅÐÐÐÐÎª
	if (Data->RequestorMode == KernelMode || FltGetRequestorProcessId(Data) == ScannerData.ClientPid || FlagOn(ulOption, FILE_DIRECTORY_FILE) ||
		FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) || FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
		FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) || FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO)
		)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	//¿ªÊ¼»ñÈ¡ÎÄ¼þµÄÒ»Ð©ÐÅÏ¢
	entry.hFile = FltObjects->FileObject;
	if (entry.hFile == NULL)
	{
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	//ÔÚÕâÀïÅÐ¶ÏÎÒÃÇÐèÒªµ¯´°µÄ²Ù×÷
	//ÕâÀïÊÇÔÚÅÐ¶ÏÈç¹ûÊÇ´´½¨²Ù×÷µÄ²Ù×÷,ÎÒÃÇ¾ÍÐèÒªµ¯´°£¬ÔÊÐí²»ÔÊÐíËüµ¯´°
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

	status = FltParseFileNameInformation(nameInfo);
	if (!NT_SUCCESS(status))
	{
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	//
	//  Check if the extension matches the list of extensions we are interested in
	//
	   //´´½¨´ò¿ªÎÄ¼þ£¬ÖØÃüÃûÎÄ¼þ¶¼ÓÐµÄ²Ù×÷
		//»ñÈ¡½ø³ÌµÄÂ·¾¶£¬


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
	
	UNICODE_STRING us_ProcessPath = { 0 };
	us_ProcessPath.Buffer = entry.ProcessPath;
	us_ProcessPath.MaximumLength = sizeof(entry.ProcessPath);
	GetProcessFullNameByPid(PsGetCurrentProcessId(), &us_ProcessPath);
	entry.option = 1;
	//	DbgPrint("Process Path: %ws \n", entry.ProcessPath);
		//»ñÈ¡ÎÄ¼þµÄÃû³Æ

	wcsncpy(entry.FilePath, nameInfo->Name.Buffer, MAX_PATH);
	if (!IsMyFilterPath(nameInfo->Name))
	{
		FltReleaseFileNameInformation(nameInfo);
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	FltReleaseFileNameInformation(nameInfo);
	if (!SearchResultList(FltObjects->FileObject, &safeToOpen))
	{
		(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
			FltObjects->FileObject,
			&entry,
			&safeToOpen);
		entry.IsOpen = safeToOpen;
		InsertResultList(safeToOpen, FltObjects->FileObject);
	}


	if (!safeToOpen) {
		DbgPrint("!!! scanner.sys -- Can't Create File precreate !!!\n");
		FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
		if (PopWindow)
		{

			fdi.DeleteFile = TRUE;
			FltSetInformationFile(FltObjects->Instance, FltObjects->FileObject, &fdi, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
		}
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ScannerPreSetInformation(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
) {
	
	UNREFERENCED_PARAMETER(CompletionContext);
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	PFLT_FILE_NAME_INFORMATION pOutReNameinfo=NULL;
	AV_GENERIC_TABLE_ENTRY  entry = { 0 };
 	BOOLEAN safeToOpen = TRUE;
	PFILE_RENAME_INFORMATION pRenameInfo;
 
	if (ScannerData.UserProcess == PsGetCurrentProcess())
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	//¿ªÊ¼»ñÈ¡ÎÄ¼þ²Ù×÷µÄÐÅÏ¢
	entry.hFile = FltObjects->FileObject;
	if (entry.hFile==NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo);

	if (!NT_SUCCESS(status)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltParseFileNameInformation(nameInfo);

	if (!NT_SUCCESS(status))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
// 
// 	//ÕâÀïÈç¹ûÊÇ´´½¨²Ù×÷¾ÍÒªµ¯´°£¬ÔÊÐí²»ÔÊÐí´´½¨£¬Èç¹ûÔÊÐí´´½¨ÁË£¬¾Í²»ÐèÒªÔÚÉ¨ÃèÎÄ¼þµÄÎÄ¼þÁ÷£¬µÈËü¹Ø±ÕµÄÊ±ºò
// 	//½øÐÐÊý¾ÝÁ÷µÄÅÐ¶Ï£¬»òÕß¶ÔËüµÄMD5£¬ÉõÖÁ¼Ó½âÃÜ²Ù×÷¡£
// 
// 	//ÐèÒªÅÐ¶ÏÈç¹ûÊÇ´´½¨²Ù×÷£¬¾Í²»½øÐÐ´ò¿ªÎÄ¼þ£¬É¨Ãè¡£Èç¹û²»ÊÇ´´½¨²Ù×÷£¬¾Í½øÐÐMD5µÈ²éÑ¯·½·¨£¬ÅÐ¶ÏÊÇËüÊÇ²»ÊÇÒ»¸öÓÐÎÊÌâµÄÎÄ¼þ¡£
// 		//´´½¨´ò¿ªÎÄ¼þ£¬ÖØÃüÃûÎÄ¼þ¶¼ÓÐµÄ²Ù×÷
// 		//»ñÈ¡½ø³ÌµÄÂ·¾¶£¬
	UNICODE_STRING us_ProcessPath = { 0 };
	us_ProcessPath.Buffer = entry.ProcessPath;
	us_ProcessPath.MaximumLength = sizeof(entry.ProcessPath);
	GetProcessFullNameByPid(PsGetCurrentProcessId(), &us_ProcessPath);
	wcsncpy(entry.FilePath, nameInfo->Name.Buffer, MAX_PATH);
	if (!IsMyFilterPath(nameInfo->Name))
	{
		FltReleaseFileNameInformation(nameInfo);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FltReleaseFileNameInformation(nameInfo);
	//»ñÈ¡²Ù×÷ÀàÐÍ	
	if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
		Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
	{
		switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
		{
		case FileRenameInformation:
		{
		entry.option = 2;
		pRenameInfo= Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
		status = FltGetDestinationFileNameInformation(FltObjects->Instance, Data->Iopb->TargetFileObject, pRenameInfo->RootDirectory, pRenameInfo->FileName, pRenameInfo->FileNameLength, FLT_FILE_NAME_NORMALIZED, &pOutReNameinfo);		
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FltGetDestinationFileNameInformation is faild! 0x%x", status);
			break;
		}
		status =FltParseFileNameInformation(pOutReNameinfo);
		if (!NT_SUCCESS(status))
		{
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		FltReleaseFileNameInformation(pOutReNameinfo);
		wcsncpy(entry.RenamePath, pOutReNameinfo->Name.Buffer, MAX_PATH);
		DbgPrint("R0 oldname %ws\n", entry.FilePath);
		DbgPrint("R0 rename %wZ\n",&pOutReNameinfo->Name);
		break;
		}

		case FileDispositionInformation:
			
			DbgPrint("R0 delete %ws\n", entry.FilePath);
			entry.option = 3;
			break;
		default:
			entry.option = 0;
			break;
		}

		

		if (!SearchResultList(FltObjects->FileObject, &safeToOpen))
		{
			(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
				FltObjects->FileObject,
				&entry,
				&safeToOpen);
			entry.IsOpen = safeToOpen;
			if (entry.option==2)
			{
				RemoveResultList(FltObjects->FileObject);
				InsertResultList(safeToOpen,Data->Iopb->TargetFileObject);
			}
			if (entry.option==3)
			{
				RemoveResultList(FltObjects->FileObject);
			}			
		}
		entry.IsOpen = safeToOpen;
		if (!safeToOpen)
		{
			DbgPrint("in PreSetInforMation !\n");
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			status = FLT_PREOP_COMPLETE;
		}
		else
		{
			status = FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	return status;

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
	BOOLEAN safeToOpen, scanFile;
	AV_GENERIC_TABLE_ENTRY entry = { 0 };




	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	//
	//  If this create was failing anyway, don't bother scanning now.
	//

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	

	//
	//  Check if we are interested in this file.
	//
	if (FltObjects->FileObject == NULL)
	{
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
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

	//»ñÈ¡½ø³ÌµÄÂ·¾¶£¬
	UNICODE_STRING us_ProcessPath = { 0 };
	us_ProcessPath.Buffer = entry.ProcessPath;
	us_ProcessPath.MaximumLength = sizeof(entry.ProcessPath);
	GetProcessFullNameByPid(PsGetCurrentProcessId(), &us_ProcessPath);
	//DbgPrint("Process Path: %ws \n", entry.ProcessPath);
	//»ñÈ¡ÎÄ¼þµÄÃû³Æ
	wcsncpy(entry.FilePath, nameInfo->Name.Buffer, MAX_PATH);

	//DbgPrint("File Path:%ws \n", entry.FilePath);

	
	if (IsMyFilterPath(nameInfo->Name))
	{
		FltReleaseFileNameInformation(nameInfo);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	FltReleaseFileNameInformation(nameInfo);
	entry.option = 0;

	if (!SearchResultList(FltObjects->FileObject, &safeToOpen))
	{
		(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
			FltObjects->FileObject,
			&entry,
			&safeToOpen);
		entry.IsOpen = safeToOpen;
		InsertResultList(safeToOpen, FltObjects->FileObject);
	}		
	
	if (!safeToOpen) {

		//
		//  Ask the filter manager to undo the create.
		//

		DbgPrint("!!! scanner.sys -- foul language detected in postcreate !!!\n");

		//Èç¹ûÊÇ´´½¨²Ù×÷£¬ÎÒÃÇ¾Ü¾øÁËÕâ¸ö´´½¨µÄ²Ù×÷£¬»¹ÐèÒªÉ¾³ýÕâ¸ö¿ÕµÄÎÄ¼þ£¬·ñÔòÉ¨ÃèÎÄ¼þµÄ»°£¬Ö»ÐèÒª¶ÔËü½øÐÐ¾Ü¾ø·ÃÎÊ²Ù×÷

		FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;

		returnStatus = FLT_POSTOP_FINISHED_PROCESSING;

	}

	//ÕâÀïÊÇÔÊÐí´´½¨ºÍ´ò¿ªÒÔºó£¬ÓÐÐ´µÄÈ¨ÏÞµÄÊ±ºò¾ÍÐèÒª¶ÔËüÉèÖÃÉÏÏÂÎÄ£¬½øÐÐÎÄ¼þÁ÷µÄÉ¨Ãè¡£
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
	AV_GENERIC_TABLE_ENTRY entry;
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);
	entry.option = 0;
	if (NT_SUCCESS(status)) {

		if (context->RescanRequired) {//Ð´¹Ø±Õ

			(VOID)ScannerpScanFileInUserMode(FltObjects->Instance,
				FltObjects->FileObject,
				&entry,
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

		 ExFreePool(notification);
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
	__in PAV_GENERIC_TABLE_ENTRY entry,
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
		switch (entry->option)
		{
		case 0:
			//É¨ÃèÎÄ¼þ
		{
			notification->Option = 0;
			wcscpy_s(notification->ProcessPath, MAX_PATH, entry->ProcessPath);
			wcscpy_s(notification->FilePath, MAX_PATH, entry->FilePath);
			break;
		}
		case 1:
			//ÕâÀïÊÇ´´½¨ÎÄ¼þ
		{
			notification->Option = 1;
			wcscpy_s(notification->ProcessPath, MAX_PATH, entry->ProcessPath);
			//DbgPrint("r0 CreateFile processpath: %ws \n", entry->ProcessPath);
			wcscpy_s(notification->FilePath, MAX_PATH, entry->FilePath);
			//DbgPrint("r0 CreateFile filepath: %ws \n", entry->FilePath);
			goto sendtor3;
		}
		case 2:
		{
			//ÕâÀïÊÇÖØÃüÃûÎÄ¼þ
			notification->Option = 2;
			wcscpy_s(notification->ProcessPath, MAX_PATH, entry->ProcessPath);
			//DbgPrint("r0 CreateFile processpath: %ws \n", entry->ProcessPath);
			wcscpy_s(notification->FilePath, MAX_PATH, entry->FilePath);
			//DbgPrint("r0 CreateFile filepath: %ws \n", entry->FilePath);
			wcscpy_s(notification->RenamePath, MAX_PATH, entry->RenamePath);
			goto sendtor3;
		}
		case 3:
		{
			notification->Option = 3;
			wcscpy_s(notification->ProcessPath, MAX_PATH, entry->ProcessPath);
			//DbgPrint("r0 CreateFile processpath: %ws \n", entry->ProcessPath);
			wcscpy_s(notification->FilePath, MAX_PATH, entry->FilePath);
			//DbgPrint("r0 CreateFile filepath: %ws \n", entry->FilePath);
			goto sendtor3;
		}
		
		default:
			break;
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



			//ÔÚÕâÀï½øÐÐÎÄ¼þÊý¾ÝµÄ¿½±´·¢ËÍµ½R3
		sendtor3:
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
		//OK
	}
	finally{

	 if (NULL != buffer) {

		 FltFreePoolAlignedWithTag(Instance, buffer, 'nacS');
	 }

	 if (NULL != notification) {

		 ExFreePool(notification);
	 }

	 if (NULL != volume) {

		 FltObjectDereference(volume);
	 }
	}

	return status;
}

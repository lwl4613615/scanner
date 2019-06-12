#include "stdafx.h"
#include "WorkThread.h"
#include <user.h>
#include <windows.h>
#include"..\\..\\inc\\scanuk.h"
#include <fltuser.h>
#pragma comment(lib,"fltLib.lib")

WorkThread::WorkThread()
{
}


WorkThread::~WorkThread()
{
}

void WorkThread::CreateConnect()
{
	//这里要开始创建完成端口

	HRESULT hr = 0;
	HANDLE port = NULL;
	HANDLE completion = NULL;
	SCANNER_THREAD_CONTEXT context = { 0 };
	HANDLE threads[SCANNER_MAX_THREAD_COUNT];
	DWORD ThreadID;
	PSCANNER_MESSAGE msg;
	int i;
	//开始连接minifilter端口
	hr = FilterConnectCommunicationPort(ScannerPortName,
		0,
		NULL,
		0,
		NULL,
		&port);
	if (IS_ERROR(hr)) {

		QMessageBox::warning(NULL, QString("error"), QString("ERROR: Connecting to filter port: 0x%1").arg(QString::number(hr, 16)));
		//printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		return;
	}
	//开始建立完成端口
	completion = CreateIoCompletionPort(port,
		NULL,
		0,
		SCANNER_DEFAULT_THREAD_COUNT);
	if (completion == NULL)
	{
		QMessageBox::warning(NULL, QString("error"), QString("ERROR: Creating completion port: %1").arg(QString::number(GetLastError(), 16)));
		CloseHandle(port);
		return;
	}
	qDebug() << "Scanner: Port = 0x%p Completion = 0x%p", port, completion;
	context.Completion = completion;
	context.Port = port;

	//开启线程
	for (i = 0; i < SCANNER_DEFAULT_THREAD_COUNT; i++)
	{
		threads[i] = CreateThread(NULL,
			0,
			(LPTHREAD_START_ROUTINE)ScannerWorker,
			&context,
			0,
			&ThreadID);

		if (threads[i] == NULL) {

			//
			//  Couldn't create thread.
			//
			QMessageBox::warning(NULL, QString("error"), QString("ERROR: Couldn't create thread:  %1").arg(QString::number(GetLastError(), 16)));
			goto cleanup;
		}
		//开始请求
		for (int j = 0; j < SCANNER_DEFAULT_REQUEST_COUNT; j++)
		{

			//开始申请内存给消息
			msg = new SCANNER_MESSAGE{ 0 };
			if (msg == NULL) {

				hr = ERROR_NOT_ENOUGH_MEMORY;
				goto cleanup;
			}
			memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));
			hr = FilterGetMessage(port,
				&msg->MessageHeader,
				FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
				&msg->Ovlp);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

				delete(msg);
				goto cleanup;
			}
		}
	}
	hr = S_OK;

	WaitForMultipleObjectsEx(i, threads, TRUE, INFINITE, FALSE);
cleanup:
	QMessageBox::warning(NULL, QString("error"), QString("Scanner:  All done. Result = 0x %1").arg(QString::number(hr, 16)));


	CloseHandle(port);
	CloseHandle(completion);
}
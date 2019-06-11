#include "stdafx.h"
#include "qtr3pop.h"
#include <QFileDialog>
#include<QMessageBox>
#include"..\\..\\inc\\scanuk.h"
#include <fltuser.h>
#pragma comment(lib,"fltLib.lib")
#include <user.h>
#include <windows.h>
#include <QThread>
#include <QObject>
#include "WorkThread.h"
//����QT�߳���




qtr3pop::qtr3pop(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	WorkThread *pWork = new WorkThread();


	//�����ʼ�¼�
	connect(ui.btn_start, &QPushButton::clicked, this,&qtr3pop::ClickStartButton);
	connect(ui.btn_stop, &QPushButton::clicked, this, &qtr3pop::ClickStopButton);
	connect(ui.btn_test, &QPushButton::clicked, pWork,&WorkThread::CreateConnect);
	QThread* pthread = new QThread(this);
	
	pWork->moveToThread(pthread);
	pthread->start();

}





void qtr3pop::ClickStartButton()
{
	
	//��ȡ�ļ�·��
	QString fileName = QFileDialog::getOpenFileName(NULL,
		tr("Open Sys File"),
		"F:",
		tr("Driver File(*.sys)"));
	QFileInfo fileinfo(fileName);
	QByteArray temp1 = fileName.toLatin1();
	QByteArray temp2 = fileinfo.baseName().toLatin1();
	char *filepath=nullptr;	
	char *drivername = nullptr;
	filepath = temp1.data();
	drivername =temp2.data();
	//��������	
	obj.DeleteDriver(drivername);
	if (obj.InstallDriver(drivername, filepath, "370020")) {
		if (obj.StartDriver(drivername))
		{
			QMessageBox::about(NULL, QString::fromLocal8Bit("����"), QString::fromLocal8Bit("�������سɹ�"));
			//��ʼ�����߳�
			
			
		}
	}
	
}

void qtr3pop::ClickStopButton()
{
	obj.StopDriver(obj.GetDriverName());
	
	if (obj.DeleteDriver(obj.GetDriverName()))
	{
		QMessageBox::about(NULL, QString::fromLocal8Bit("�ر�"), QString::fromLocal8Bit("�����رճɹ�"));;
	}
	
}


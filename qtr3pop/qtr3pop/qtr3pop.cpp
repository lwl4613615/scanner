#include "stdafx.h"
#include "qtr3pop.h"
#include <QFileDialog>
#include<QMessageBox>

#include <QThread>
#include <QObject>

//创建QT线程类




qtr3pop::qtr3pop(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	
	pWork = new WorkThread();
	
	
	//点击开始事件
	connect(ui.btn_start, &QPushButton::clicked, this,&qtr3pop::ClickStartButton);
	connect(ui.btn_stop, &QPushButton::clicked, this, &qtr3pop::ClickStopButton);
	QThread* pthread = new QThread(this);
	pWork->moveToThread(pthread);
	pthread->start();
	connect(this, &qtr3pop::beginthread, pWork, &WorkThread::CreateConnect);
	
}





void qtr3pop::ClickStartButton()
{
	
	//获取文件路径
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
	//加载驱动	
	obj.DeleteDriver(drivername);
	if (obj.InstallDriver(drivername, filepath, "370020")) {
		if (obj.StartDriver(drivername))
		{
			QMessageBox::about(NULL, QString::fromLocal8Bit("开启"), QString::fromLocal8Bit("驱动加载成功"));			
			//开启弹窗的线程
			emit beginthread();
		}
	}	
	
}

void qtr3pop::ClickStopButton()
{
	obj.StopDriver(obj.GetDriverName());
	
	if (obj.DeleteDriver(obj.GetDriverName()))
	{
		QMessageBox::about(NULL, QString::fromLocal8Bit("关闭"), QString::fromLocal8Bit("驱动关闭成功"));;
	}
	
}


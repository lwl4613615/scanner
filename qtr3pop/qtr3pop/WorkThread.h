#pragma once
#include <QObject>
class WorkThread:public QObject
{
	Q_OBJECT
public:
	WorkThread();
	~WorkThread();
public slots:
	void CreateConnect();
};


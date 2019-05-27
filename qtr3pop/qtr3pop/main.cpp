#include "stdafx.h"
#include "qtr3pop.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	qtr3pop w;
	w.show();
	return a.exec();
}

#pragma once

#include <QtWidgets/QMainWindow>

#include "ui_qtr3pop.h"
#include "Driver.h"

//
//  Default and Maximum number of threads.
//





class qtr3pop : public QMainWindow
{
	Q_OBJECT

public:
	qtr3pop(QWidget *parent = Q_NULLPTR);
private slots:
	void ClickStartButton();
	void ClickStopButton();

	
private:
	Ui::qtr3popClass ui;
	Driver obj;
};
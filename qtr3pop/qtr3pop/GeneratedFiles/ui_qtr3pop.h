/********************************************************************************
** Form generated from reading UI file 'qtr3pop.ui'
**
** Created by: Qt User Interface Compiler version 5.12.3
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QTR3POP_H
#define UI_QTR3POP_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_qtr3popClass
{
public:
    QWidget *centralWidget;
    QGridLayout *gridLayout;
    QPushButton *btn_start;
    QPushButton *btn_stop;

    void setupUi(QMainWindow *qtr3popClass)
    {
        if (qtr3popClass->objectName().isEmpty())
            qtr3popClass->setObjectName(QString::fromUtf8("qtr3popClass"));
        qtr3popClass->resize(201, 134);
        centralWidget = new QWidget(qtr3popClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        gridLayout = new QGridLayout(centralWidget);
        gridLayout->setSpacing(6);
        gridLayout->setContentsMargins(11, 11, 11, 11);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        btn_start = new QPushButton(centralWidget);
        btn_start->setObjectName(QString::fromUtf8("btn_start"));

        gridLayout->addWidget(btn_start, 0, 0, 1, 1);

        btn_stop = new QPushButton(centralWidget);
        btn_stop->setObjectName(QString::fromUtf8("btn_stop"));

        gridLayout->addWidget(btn_stop, 0, 1, 1, 1);

        qtr3popClass->setCentralWidget(centralWidget);

        retranslateUi(qtr3popClass);

        QMetaObject::connectSlotsByName(qtr3popClass);
    } // setupUi

    void retranslateUi(QMainWindow *qtr3popClass)
    {
        qtr3popClass->setWindowTitle(QApplication::translate("qtr3popClass", "qtr3pop", nullptr));
        btn_start->setText(QApplication::translate("qtr3popClass", "\345\274\200\345\247\213", nullptr));
        btn_stop->setText(QApplication::translate("qtr3popClass", "\345\201\234\346\255\242", nullptr));
    } // retranslateUi

};

namespace Ui {
    class qtr3popClass: public Ui_qtr3popClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QTR3POP_H

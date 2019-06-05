#ifndef WIDGET_H
#define WIDGET_H
#pragma once
#include <QWidget>
#include"Driver.h"
namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = nullptr);
    ~Widget();
private slots:
    void btnclickstart();
    void btnclickstop();
private:
    Driver obj;
private:
    Ui::Widget *ui;
};

#endif // WIDGET_H

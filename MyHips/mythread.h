#ifndef MYTHREAD_H
#define MYTHREAD_H
#pragma once
#include <QObject>
#include<Windows.h>

class mythread : public QObject
{
    Q_OBJECT
public:
    explicit mythread(QObject *parent = nullptr);
    void beginlisten();
signals:

public slots:
};

#endif // MYTHREAD_H

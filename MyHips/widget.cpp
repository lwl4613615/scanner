#include "widget.h"
#include "ui_widget.h"

#include<QFileInfo>
#include<QByteArray>
#include<QFileDialog>
#include<QMessageBox>
Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);

    //connect functions
    connect(ui->btn_start,&QPushButton::clicked,this,&Widget::btnclickstart);


}
Widget::~Widget()
{
    delete ui;
}
void Widget::btnclickstart()
{
    //there is start service
    //获取文件路径
        QString fileName = QFileDialog::getOpenFileName(nullptr,
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
                QMessageBox::about(nullptr, QString::fromLocal8Bit("开启"), QString::fromLocal8Bit("驱动加载成功"));
                ui->btn_stop->setEnabled(true);
                //开始创建线程


            }
        }

}

void Widget::btnclickstop()
{
    //there is stop  service
    obj.StopDriver(obj.GetDriverName());

        if (obj.DeleteDriver(obj.GetDriverName()))
        {
            QMessageBox::about(nullptr, QString::fromLocal8Bit("关闭"), QString::fromLocal8Bit("驱动关闭成功"));
            //如果成功了这个按钮就不再显示了
            ui->btn_stop->setEnabled(false);
        }

}

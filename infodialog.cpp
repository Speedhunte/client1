#include "infodialog.h"
#include "ui_infodialog.h"

InfoDialog::InfoDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InfoDialog)
{
    ui->setupUi(this);
}

InfoDialog::~InfoDialog()
{
    delete ui;
}

void InfoDialog::SetUsername(QString const &username)
{
    ui->username_label->setText(username);
}
void InfoDialog::SetDateTime(QString const &date_time)
{
    ui->date_time_label->setText(date_time);
}
void InfoDialog::SetIp(QString const &ip)
{
    ui->ip_label->setText(ip);
}
void InfoDialog::SetStatus(QString const &status)
{
    ui->status_label->setText(status);
}

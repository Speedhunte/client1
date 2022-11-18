#pragma once

#include <QDialog>

namespace Ui {
class InfoDialog;
}

class InfoDialog : public QDialog
{
    Q_OBJECT

public:
    explicit InfoDialog(QWidget *parent = nullptr);
    ~InfoDialog();

    void SetUsername(QString const &username);
    void SetDateTime(QString const &date_time);
    void SetIp(QString const &ip);
    void SetStatus(QString const &status);


private:
    Ui::InfoDialog *ui;
};

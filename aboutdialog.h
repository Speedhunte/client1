#pragma once

#include <QDialog>

namespace Ui {
class AboutDialog;
}

class AboutDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AboutDialog(QWidget *parent = nullptr);
    ~AboutDialog();

    void SetVersion(QString const &version);

private:
    Ui::AboutDialog *ui;
};

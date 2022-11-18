#pragma once

#include <QMainWindow>
#include <QPointer>

#include "global.h"

class QSslSocket;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    void UpdateWindowTitle(bool connected);
    void ProcessStatus(QSslSocket *socket, QDataStream &in);
    void ProcessUsername(QSslSocket *socket, QDataStream &in);
    void ProcessInvalidUsername(QSslSocket *socket, QDataStream &in);
    void ProcessUserAdded(QSslSocket *socket, QDataStream &in);
    void ProcessUserRemoved(QSslSocket *socket, QDataStream &in);
    void ProcessMessage(QSslSocket *socket, QDataStream &in);

    Ui::MainWindow *ui;

    QPointer <QSslSocket> socket_;
    quint16 port_;
    QString ip_;
    QString username_;
    QString status_;

private slots:
    void WaitForUsername();
    void Read();
};

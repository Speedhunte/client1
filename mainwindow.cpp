#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslCipher>
#include <QSslPreSharedKeyAuthenticator>
#include <QMessageBox>
#include <QHostAddress>
#include <QStandardItemModel>
#include <QDateTime>
#include <QSound>
#include <QXmlStreamWriter>
#include <QFile>
#include <QSettings>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "usernamedialog.h"
#include "connectionsettingsdialog.h"
#include "aboutdialog.h"
#include "infodialog.h"
#include "xmldialog.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , status_("Доступен")
{
    ui->setupUi(this);

    //Чтение значений из файла конфигруации
    QSettings s("config", QSettings::IniFormat);
    port_ = s.value("port", 45678).toUInt();
    ip_ = s.value("ip", "127.0.0.1").toString();
    username_ = s.value("username", "user").toString();

    //Создание списка пользователей(пока пустой)
    QStandardItemModel *model = new QStandardItemModel;
    model->setColumnCount(1);
    ui->users_list_view->setModel(model);

    connect(ui->connect_action, &QAction::triggered, [this]
    {
        //Выбор протокола и алгоритма шифрования для соединения с сервером
        socket_ = new QSslSocket;
        QSslConfiguration conf;
        conf.setProtocol(QSsl::TlsV1_2);
        conf.setPeerVerifyMode(QSslSocket::VerifyNone);
        QList <QSslCipher> ciphers;
        for (auto &cipher : conf.supportedCiphers())
        {
            if (cipher.name() == CIPHER_NAME) ciphers.push_back(cipher);
        }
        if (!ciphers.empty())
        {
            conf.setCiphers(ciphers);
        }
        else
        {
            QMessageBox::critical(nullptr, "Критическая ошибка!", "Ошибка выбора алгоритма шифрования.");
            QApplication::exit(1);
        }
        socket_->setSslConfiguration(conf);

        connect(socket_, QOverload <const QList <QSslError> &>::of(&QSslSocket::sslErrors), [](const QList <QSslError> & /*errors*/)
        {
            QMessageBox::critical(nullptr, "Ошибка", "Ошибка установления защищённого соединения");
        });
        connect(socket_, QOverload <QAbstractSocket::SocketError>::of(&QSslSocket::errorOccurred), [this](QAbstractSocket::SocketError error)
        {
            if (error == QAbstractSocket::SocketError::RemoteHostClosedError)
            {
                //Например, если закрыть сервер при имеющемся соединении с клиентом
                ui->disconnect_action->setEnabled(false);
                ui->send_push_button->setEnabled(false);
                connect(socket_, &QSslSocket::disconnected, [this]
                {
                    //Возврат в состояние "не подключен"
                    status_ = "Доступен";
                    ui->connect_action->setEnabled(true);
                    ui->server_action->setEnabled(true);
                    ui->available_action->setEnabled(false);
                    ui->moved_away_action->setEnabled(false);
                    ui->do_not_disturb_action->setEnabled(false);
                    ui->available_action->setChecked(true);
                    ui->moved_away_action->setChecked(false);
                    ui->do_not_disturb_action->setChecked(false);
                    ui->users_list_view->model()->removeRows(0, ui->users_list_view->model()->rowCount());
                    socket_.clear();
                    ui->main_text_edit->append("Потеряно соединение с сервером.");
                    UpdateWindowTitle(false);
                });
                socket_->disconnectFromHost();
            }
            else if (error == QAbstractSocket::SocketError::ConnectionRefusedError)
            {
                ui->main_text_edit->append("Сервер не найден!");
            }
        });
        connect(socket_, &QSslSocket::preSharedKeyAuthenticationRequired, this, [](QSslPreSharedKeyAuthenticator* authenticator)
        {
            //Ключ, одинаковый на клиенте и сервере, нужен для идентификации клиента
            authenticator->setIdentity("XmlTLSClientServer");
            authenticator->setPreSharedKey(QByteArrayLiteral("XmlTLSClientServer"));
        });
        connect(socket_, &QSslSocket::encrypted, [this]
        {
            //Соединение успешно зашифровано, теперь можно дожидаться получение имени пользователя
            ui->connect_action->setEnabled(false);
            ui->server_action->setEnabled(false);
            ui->main_text_edit->append("Соединение с сервером установлено.");
            connect(socket_, &QSslSocket::readyRead, this, &MainWindow::WaitForUsername);

            QByteArray ba; // передает имя поьзователя серверу
            QDataStream out(&ba, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_5_15);
            out << quint16(0) << username_;

            out.device()->seek(0);
            out << quint16(ba.size() - sizeof(quint16));
            socket_->write(ba);
        });

        socket_->connectToHostEncrypted(ip_, port_);
    });
    connect(ui->disconnect_action, &QAction::triggered, [this]
    {
        ui->disconnect_action->setEnabled(false);
        ui->send_push_button->setEnabled(true);
        ui->main_text_edit->append("Отключение от сервера...");
        connect(socket_, &QSslSocket::disconnected, [this]
        {
            //Отключение от сервера
            status_ = "Доступен";
            ui->connect_action->setEnabled(true);
            ui->server_action->setEnabled(true);
            ui->available_action->setEnabled(false);
            ui->moved_away_action->setEnabled(false);
            ui->do_not_disturb_action->setEnabled(false);
            ui->available_action->setChecked(true);
            ui->moved_away_action->setChecked(false);
            ui->do_not_disturb_action->setChecked(false);
            ui->users_list_view->model()->removeRows(0, ui->users_list_view->model()->rowCount());
            socket_.clear();
            ui->main_text_edit->append("Соединение закрыто.");
            UpdateWindowTitle(false);
        });
        socket_->disconnectFromHost();
    });

    auto StatusTriggered = [this](QAction *action)
    {
        //Запрос на изменение статусв
        Status new_status;
        if (action == ui->available_action) new_status = kAvailable;
        else if (action == ui->moved_away_action) new_status = kMovedAway;
        else if (action == ui->do_not_disturb_action) new_status = kDoNotDisturb;
        action->setChecked(false);

        QByteArray ba;
        QDataStream out(&ba, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << quint16(0) << kStatus << new_status;

        out.device()->seek(0);
        out << quint16(ba.size() - sizeof(quint16));
        socket_->write(ba);
    };
    connect(ui->available_action, &QAction::triggered, [this, StatusTriggered]() { StatusTriggered(ui->available_action); });
    connect(ui->moved_away_action, &QAction::triggered, [this, StatusTriggered]() { StatusTriggered(ui->moved_away_action); });
    connect(ui->do_not_disturb_action, &QAction::triggered, [this, StatusTriggered]() { StatusTriggered(ui->do_not_disturb_action); });

    connect(ui->username_action, &QAction::triggered, [this]
    {
        //Диалоговое окно для изменения имени пользователя
        //Если соединение установлено, отправит запрос на изменение имени пользователя на введённое
        UsernameDialog dlg;
        dlg.SetUsername(username_);
        if (dlg.exec() == QDialog::Accepted)
        {
            if (socket_)
            {
                QByteArray ba;
                QDataStream out(&ba, QIODevice::WriteOnly);
                out.setVersion(QDataStream::Qt_5_15);
                out << quint16(0) << kUsername << dlg.Username();

                out.device()->seek(0);
                out << quint16(ba.size() - sizeof(quint16));
                socket_->write(ba);
            }
            else username_ = dlg.Username();
        }
    });

    connect(ui->server_action, &QAction::triggered, [this]
    {
        //Диалоговое окно настроек адреса и порта сервера
        ConnectionSettingsDialog dlg;
        dlg.SetIp(ip_);
        dlg.SetPort(port_);
        if (dlg.exec() == QDialog::Accepted)
        {
            ip_ = dlg.Ip();
            port_ = dlg.Port();
        }
    });

    connect(ui->send_push_button, &QPushButton::clicked, [this]
    {
        //Отправка сообщения в чат

        if (ui->message_line_edit->text().isEmpty()) return;

        QByteArray ba;
        QDataStream out(&ba, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << quint16(0) << kMessage << ui->message_line_edit->text();

        out.device()->seek(0);
        out << quint16(ba.size() - sizeof(quint16));
        socket_->write(ba);

        ui->message_line_edit->clear();
    });

    connect(ui->about_action, &QAction::triggered, []
    {
        //Диалоговое окно "о программе"

        AboutDialog dlg;
        dlg.SetVersion(QT_VERSION_STR);
        dlg.exec();
    });
    connect(ui->exit_action,&QAction::triggered, []
    {
        //выход из приложения
        QApplication::exit();
    });
    connect(ui->users_list_view, &QListView::clicked, [](QModelIndex const &index)
    {
        //Вывод диалогового окна с информацией о пользователе
        QStringList info = index.data(Qt::UserRole).toStringList();

        InfoDialog dlg;
        dlg.SetUsername(index.data().toString());
        dlg.SetDateTime(info[0]);
        dlg.SetIp(info[2]);
        dlg.SetStatus(info[1]);
        dlg.exec();
    });

    connect(ui->xml_action, &QAction::triggered, [this]
    {
        //Диалоговое окно с вводом имени файла и пароля
        //при закрытии создаст и зашифрует все сообщения на клиенте в xml файл с введённым именем с помощью алгоритма aes
        //ключом, полученным из введённого пароля

        auto aes_init = [](unsigned char const *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
                           EVP_CIPHER_CTX *d_ctx) // преобразует ключ
        {
            //Инициализация параметров шифрования и преобразование пароля в ключ(хэшированием)

            int i, nrounds = 5;
            unsigned char key[32], iv[32];

            i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
            if (i != 32)
            {
                return -1;
            }

            EVP_CIPHER_CTX_init(e_ctx);
            EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
            EVP_CIPHER_CTX_init(d_ctx);
            EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

            return 0;
        };

        auto aes_encrypt = [](EVP_CIPHER_CTX *e, unsigned char const *plaintext, int *len)
        {
            //функция шифрования

            int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
            unsigned char *ciphertext = new unsigned char[c_len];

            EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

            EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

            EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

            *len = c_len + f_len;
            return ciphertext;
        };

        /*auto aes_decrypt = [](EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
        {
            //функция расшифровки

            int p_len = *len, f_len = 0;
            unsigned char *plaintext = new unsigned char[p_len];

            EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
            EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
            EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

            *len = p_len + f_len;
            return plaintext;
        };*/

        XmlDialog dlg;
        if (dlg.exec() == QDialog::Accepted)
        {
            QString filename = dlg.Filename();
            QString password = dlg.Password();

            QFile out(filename);
            if (!out.open(QIODevice::WriteOnly))
            {
                QMessageBox::critical(nullptr, "Ошибка", "Запись в файл не удалась!");
                return;
            }

            //Запись в файл
            QXmlStreamWriter writer(&out);
            writer.setAutoFormatting(true);
            writer.writeStartDocument();
            writer.writeStartElement("Client History");
            QStringList messages = ui->main_text_edit->toPlainText().split("\n");

            EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();

            unsigned int salt[] = {45678, 87654};
            unsigned char const *key_data;
            int key_data_len;

            key_data = (unsigned char const *)password.toLatin1().toStdString().c_str();
            key_data_len = strlen((const char *)key_data);

            if (aes_init(key_data, key_data_len, (unsigned char *)&salt, en, de))
            {
                return;
            }

            for (auto &message : messages)
            {
                //построчно шифруем и пишем данные в файл, оборачивая каждую строку в тег message

                writer.writeStartElement("Message");

                //char *plaintext;
                unsigned char *ciphertext;
                int /*olen,*/ len;

                const unsigned char *msg = (const unsigned char *)message.toLatin1().toStdString().c_str();
                /*olen =*/ len = strlen((const char *)msg) + 1;

                ciphertext = aes_encrypt(en, msg, &len);
                //plaintext = (char *)aes_decrypt(de, ciphertext, &len);

                writer.writeCharacters((char *)ciphertext);

                delete[] ciphertext;
                //delete[] plaintext;

                writer.writeEndElement();
            }

            //освобождение памяти, выделенной для шифрования и добавление закрывающего тега в файл
            EVP_CIPHER_CTX_free(en);
            EVP_CIPHER_CTX_free(de);

            writer.writeEndElement();
        }
    });

}

MainWindow::~MainWindow()
{
    delete ui;

    //Сохранение текущих настроек в файл конфигурации
    QSettings s("config", QSettings::IniFormat);
    s.setValue("port", port_);
    s.setValue("ip", ip_);
    s.setValue("username", username_);
}

void MainWindow::UpdateWindowTitle(bool connected)
{
    //Обновление заголовка окна
    if (connected)
    {
        setWindowTitle(QString("ip:%1, port:%2, status: %3").arg(socket_->peerAddress().toString())
                       .arg(socket_->peerPort())
                       .arg(status_));
    }
    else setWindowTitle("XmlTlsClient");
}

void MainWindow::ProcessStatus(QSslSocket * /*socket*/, QDataStream &in)
{
    //С сервера пришло сообщение о том, что нужно поменять статус(свой или другого пользователя)
    //приходит в ответ на запрос смены статуса от клиента(валидация)
    QString username;
    QString status;
    in >> username >> status;

    if (username == username_)
    {
        //нужно поменять именно свой статус
        auto UpdateStatus = [this](QString status, bool check)
        {
            if (status == "Доступен")
            {
                ui->available_action->setEnabled(!check);
                ui->available_action->setChecked(check);
            }
            else if (status == "Отошёл")
            {
                ui->moved_away_action->setEnabled(!check);
                ui->moved_away_action->setChecked(check);
            }
            else if (status == "Не беспокоить")
            {
                ui->do_not_disturb_action->setEnabled(!check);
                ui->do_not_disturb_action->setChecked(check);
            }
        };
        UpdateStatus(status_, false);
        UpdateStatus(status, true);
        status_ = status;
    }

    //Ищем в списке пользователей того пользователя, у которого поменялся статус и обновляем данные
    QAbstractItemModel *model = ui->users_list_view->model();
    for (int i = 0; i < model->rowCount(); ++i)
    {
        QModelIndex index = model->index(i, 0);
        if (index.data().toString() == username)
        {
            QStringList date_time_status_ip = index.data(Qt::UserRole).toStringList();
            date_time_status_ip[1] = status;
            model->setData(index, date_time_status_ip, Qt::UserRole);
            break;
        }
    }

    UpdateWindowTitle(true);
    ui->main_text_edit->append(QString("Пользователь %1 меняет свой статус на %2.").arg(username).arg(status));
}

void MainWindow::ProcessUsername(QSslSocket * /*socket*/, QDataStream &in)
{
    //С сервера пришло сообщение о том, что нужно поменять имя пользователя(своё или другого пользователя)
    //приходит в ответ на запрос смены имени пользователя от клиента(валидация)
    QString old_username, username;
    in >> old_username >> username;

    if (old_username == username_)
    {
        username_ = username;
    }

    //Ищем в списке пользователей того пользователя, у которого поменялось имя и обновляем данные
    QAbstractItemModel *model = ui->users_list_view->model();
    for (int i = 0; i < model->rowCount(); ++i)
    {
        QModelIndex index = model->index(i, 0);
        if (index.data().toString() == old_username)
        {
            model->setData(index, username);
            break;
        }
    }

    ui->main_text_edit->append(QString("Пользователь %1 меняет имя пользователя на %2.").arg(old_username).arg(username));
}

void MainWindow::ProcessInvalidUsername(QSslSocket * /*socket*/, QDataStream & /*in*/)
{
    //Имя пользователя оказалось занято, поэтому ничего не делаем, просто выводим информацию об этом
    ui->main_text_edit->append(QString("Не удалось сменить имя пользователя."));
}

void MainWindow::ProcessUserAdded(QSslSocket * /*socket*/, QDataStream &in)
{
    //С сервера пришло сообщение о том, что был добавлен новый пользователь

    QDateTime date_time;
    Status status;
    QString username;
    QString ip;

    in >> ip >> date_time >> status >> username;

    //Добавление пользователя в список пользователей и сохранение всей имеющейся информации о нём
    QAbstractItemModel *model = ui->users_list_view->model();
    model->insertRow(model->rowCount());
    QModelIndex index = model->index(model->rowCount() - 1, 0);
    model->setData(index, username);
    QStringList info;
    QString status_string;
    switch (status)
    {
    case kAvailable:
        status_string = "Доступен";
        break;
    case kMovedAway:
        status_string = "Отошёл";
        break;
    case kDoNotDisturb:
        status_string = "Не беспокоить";
        break;
    }
    info << date_time.toString() << status_string << ip;
    model->setData(index, info, Qt::UserRole);

    ui->main_text_edit->append(QString("Пользователь %1 зашёл на сервер.").arg(username));
}

void MainWindow::ProcessUserRemoved(QSslSocket * /*socket*/, QDataStream &in)
{
    //С сервера пришло сообщение о том, что один из пользователей вышел с сервера

    QString username;
    in >> username;

    //нужно удалить этого пользователя из списка пользователей
    QAbstractItemModel *model = ui->users_list_view->model();
    for (int i = 0; i < model->rowCount(); ++i)
    {
        if (model->index(i, 0).data().toString() == username)
        {
            model->removeRow(i);
            break;
        }
    }

    ui->main_text_edit->append(QString("Пользователь %1 вышел с сервера.").arg(username));
}

void MainWindow::ProcessMessage(QSslSocket * /*socket*/, QDataStream &in)
{
    //Пришло текстовое сообщение(своё или другого пользователя)

    QString ip, username, date_time, msg;
    in >> ip >> username >> date_time >> msg;

    ui->main_text_edit->append(QString("%1 %2(%3): %4").arg(date_time).arg(username).arg(ip).arg(msg));
    //Если сообщение от другого пользователя и статус не "Не беспокоить", проигрывается звук
    if (username != username_ && status_ != "Не беспокоить") QSound::play(":/sound.wav");
}

void MainWindow::WaitForUsername()
{
    //Пришёл ответ сервера об успешном(или нет) соединении

    QDataStream in(socket_);
    in.setVersion(QDataStream::Qt_5_15);

    quint16 block_size = 0;
    for (;;)
    {
        if (!block_size)
        {
            if (socket_->bytesAvailable() < (qint64)sizeof(quint16)) break;
            in >> block_size;
        }
        if (socket_->bytesAvailable() < block_size) break;

        MessageType message_type;
        QString msg;
        in >> message_type >> msg;

        if (message_type == kHello)
        {
            //Соединение успешно
            //Чтение списка с информацией о пользователях
            //и добавление в список пользователей
            QList <QStringList> infos;
            in >> infos;

            auto *model = ui->users_list_view->model();
            model->insertRows(0, infos.size());
            int i = 0;
            for (auto &info : infos)
            {
                QModelIndex index = model->index(i, 0);
                model->setData(index, info[3]);
                model->setData(index, (QStringList)info.mid(0, info.size() - 1), Qt::UserRole);
                ++i;
            }

            disconnect(socket_, &QSslSocket::readyRead, this, &MainWindow::WaitForUsername);
            connect(socket_, &QSslSocket::readyRead, this, &MainWindow::Read);
            ui->main_text_edit->append(msg);

            ui->disconnect_action->setEnabled(true);
            ui->moved_away_action->setEnabled(true);
            ui->do_not_disturb_action->setEnabled(true);
            ui->send_push_button->setEnabled(true);
            UpdateWindowTitle(true);
        }
        else if (message_type == kInvalidHello)
        {
            //Соединение отклонено
            ui->main_text_edit->append(msg);
            ui->disconnect_action->triggered();
            break;
        }
    }
}

void MainWindow::Read()
{
    //Функция чтения и обработки любого сообщения, пришедшего с сервера

    QSslSocket *socket = dynamic_cast <QSslSocket *> (sender());
    QDataStream in(socket);
    in.setVersion(QDataStream::Qt_5_15);

    quint16 block_size = 0;
    for (;;)
    {
        if (!block_size)
        {
            if (socket->bytesAvailable() < (qint64)sizeof(quint16)) break;
            in >> block_size;
        }
        if (socket->bytesAvailable() < block_size) break;

        MessageType message_type;
        in >> message_type;

        //В зависимости от типа пришедшего сообщения осуществляется дальнейшая обработка
        switch (message_type)
        {
        case kStatus:
            ProcessStatus(socket, in);
            break;
        case kUsername:
            ProcessUsername(socket, in);
            break;
        case kInvalidUsername:
            ProcessInvalidUsername(socket, in);
            break;
        case kUserAdded:
            ProcessUserAdded(socket, in);
            break;
        case kUserRemoved:
            ProcessUserRemoved(socket, in);
            break;
        case kMessage:
            ProcessMessage(socket, in);
            break;
        case kInfo:
            break;
        case kHello:
            break;
        case kInvalidHello:
            break;
        }
    }
}

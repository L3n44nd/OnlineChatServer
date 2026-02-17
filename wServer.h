#pragma once

#include <QtNetwork/qtcpserver.h>
#include <QtNetwork/qtcpsocket.h>
#include <QtWidgets/QWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QString>
#include <QtSql>
#include "ui_wServer.h"
#include "protocol.h"

class wServerClass : public QWidget
{
    Q_OBJECT

public:
    wServerClass(QWidget *parent = nullptr);
    ~wServerClass();

private slots:
    void onNewConnection();

private:
    QSqlDatabase chatDB;
    QTcpServer server;
    Ui::wServerClass ui;

    QHash<QTcpSocket*, QString> clients;
    QHash<QString, QTcpSocket*> clientToSocket;
    QHash<QString, std::function<void(QTcpSocket*, const QString&)>> commandsHandler;
    QSet<QString> nameSet;

    void setupDB();
    void setupUI();
    void setupServer();

    void processClientMsg(QTcpSocket* client);

    void handleRegistration(QTcpSocket* client, QString msg);
    void handleNameChange(QTcpSocket* client, QString msg);
    void handleLogin(QTcpSocket* client, QString msg);
    void handleChatMsg(QTcpSocket* client, QString msg);
    void handlePrivateMsg(QTcpSocket* client, QString msg); 
    void handleLogout(QTcpSocket* client, QString msg);
};


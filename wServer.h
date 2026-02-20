#pragma once

#include <QtNetwork/qtcpserver.h>
#include <QtNetwork/qtcpsocket.h>
#include <QString>
#include <QtSql>
#include "ui_wServer.h"
#include "\repos\wServer\Common\protocol.h"

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
    QTimer* updateOnlineNum;

    QHash<QTcpSocket*, int> socketToId;
    QHash<int, QTcpSocket*> idToSocket;
    QHash<int, QString> idToName;

    void setupDB();
    void setupServer();
    void setupTimer();

    void processClientMsg(QTcpSocket* client);
    
    void handleRegistration(QTcpSocket* client, QString msg);
    void handleNameChange(QTcpSocket* client, QString msg);
    void handleLogin(QTcpSocket* client, QString msg);
    void handleChatMsg(QTcpSocket* client, QString msg);
    void handlePrivateMsg(QTcpSocket* client, QString msg); 
    void handleLogout(QTcpSocket* client, QString msg);
    QString generateSalt();

    void qLogger(QTcpSocket* client, const clientQuery query);
    void rLogger(QTcpSocket* client, const serverResponse response);
};



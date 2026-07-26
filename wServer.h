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
    struct clientState {
        qint32 sizeOfData = 0;
        bool waitingForSize = true;
    };

    QSqlDatabase chatDB;
    QTcpServer server;
    Ui::wServerClass ui;
    QTimer* updateOnlineNum;
    QTimer* cleanUpDB;

    QHash<QTcpSocket*, int> socketToId;
    QHash<int, QTcpSocket*> idToSocket;
    QHash<int, QString> idToName;

    void setupDB();
    void setupServer();
    void setupTimers();

    void processClientMsg(QTcpSocket* client, const QByteArray& utf8msg);

    void handleRegistration(QTcpSocket* client, const QString& msg);
    void handleNameChange(QTcpSocket* client, QString& msg);
    void handleLogin(QTcpSocket* client, const QString& msg);
    void handleChatMsg(QTcpSocket* client, const QString& msg);
    void handlePrivateMsg(QTcpSocket* client, const QString& msg);
    void handleLogout(QTcpSocket* client, const QString& msg);
    void sendOnlineList();
    void sendPacket(QTcpSocket* client, const serverResponse response, const QString& data = QString());
    void sendHistory(QTcpSocket* client, const QString& msg);

    void saveToDB(const int senderId, const QString& senderName, const int recipientId, const QString& msg);
    QString generateSalt();

    void qLogger(QTcpSocket* client, const clientQuery query);
    void rLogger(QTcpSocket* client, const serverResponse response);
};


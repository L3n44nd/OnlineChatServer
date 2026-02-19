#include "wServer.h"
#include <QCryptographicHash>

wServerClass::wServerClass(QWidget* parent)
    : QWidget(parent) {

        setupDB();
        setupUI();
        setupServer();
    }

void wServerClass::setupDB() {
    chatDB = QSqlDatabase::addDatabase("QSQLITE");
    chatDB.setDatabaseName("chat.db");
    if (!chatDB.open()) {
        ui.oField->append("Не удалось открыть БД");
        return;
    }
    QSqlQuery query;
    query.exec(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE, "
        "password TEXT,"
        "salt TEXT)"
    );
}

void wServerClass::setupUI() {
    ui.setupUi(this);
    ui.oField->setReadOnly(true);
    ui.onlineField->setReadOnly(true);
}

void wServerClass::setupServer() {    
    server.listen(QHostAddress::LocalHost, 1402);
    connect(&server, &QTcpServer::newConnection, this, &wServerClass::onNewConnection);
}

void wServerClass::onNewConnection() {
    QTcpSocket* newClient = server.nextPendingConnection();
    connect(newClient, &QTcpSocket::readyRead, this, [this, newClient]() {
        processClientMsg(newClient);
        });

    connect(newClient, &QTcpSocket::disconnected, this, [this, newClient]() {
        if (socketToId.contains(newClient)) {
            int userId = socketToId[newClient];
            ui.oField->append(QString("Клиент id%1 отключился.").arg(userId));
            idToName.remove(userId);
            idToSocket.remove(userId);
            socketToId.remove(newClient);
        }
        newClient->deleteLater();
        });
}

void wServerClass::processClientMsg(QTcpSocket* client) {
    QByteArray utf8msg = client->readAll();
    QString strmsg = QString::fromUtf8(utf8msg);
    int code = strmsg.section(' ', 0, 0).toInt(); 
    QString textMsg = strmsg.section(' ', 1);
    clientQuery command = static_cast<clientQuery>(code);

    switch (command)
    {
    case clientQuery::Register:
        handleRegistration(client, textMsg);
        break;
    case clientQuery::Login:
        handleLogin(client, textMsg);
        break;
    case clientQuery::Logout:
        handleLogout(client, textMsg);
        break;
    case clientQuery::Message:
        handleChatMsg(client, textMsg);
        break;
    case clientQuery::PrivateMessage:
        handlePrivateMsg(client, textMsg);
        break;
    case clientQuery::NameChange:
        handleNameChange(client, textMsg);
        break;
    default:
        break;
    }
}

void wServerClass::handleRegistration(QTcpSocket* client, QString msg) {
    QStringList msgParts = msg.split(' '); 
    QString username = msgParts[0];
    QString password = msgParts[1];
    
    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", username);
    checkQuery.exec();

    int respCode = -1;
    int userId;
    bool regSuccessful = false;

    if (checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        QString salt = generateSalt();
        QString strToHash = password + salt;
        QByteArray bArrHashedStr = QCryptographicHash::hash(strToHash.toUtf8(), QCryptographicHash::Sha256);
        QString strHashed = bArrHashedStr.toHex();

        QSqlQuery regQuery;
        regQuery.prepare("INSERT INTO users (username, password, salt) VALUES (:name, :psw, :slt)");
        regQuery.bindValue(":name", username);
        regQuery.bindValue(":psw", strHashed);
        regQuery.bindValue(":slt", salt);
        regQuery.exec();

        userId = regQuery.lastInsertId().toInt();
        idToName[userId] = username;
        idToSocket[userId] = client;
        socketToId[client] = userId;

        respCode = static_cast<int>(serverResponse::Registered);
        regSuccessful = true;
    }
    else {
        respCode = static_cast<int>(serverResponse::UsernameExists);
    }

    QByteArray response;
    if (regSuccessful) {
        QString formatedMsg = QString("%1 %2 %3").arg(respCode).arg(userId).arg(username);
        response = formatedMsg.toUtf8();
    }
    else {
        response = QByteArray::number(respCode);
    }
    client->write(response);
}

void wServerClass::handleLogin(QTcpSocket* client, QString msg) {
    QStringList msgParts = msg.split(' ');
    QString username = msgParts[0];
    QString password = msgParts[1];

    int respCode = -1;
    int userId;
    bool loginSuccessful = false;
    

    QSqlQuery checkDataQuery;
    checkDataQuery.prepare("SELECT password, salt, id FROM users WHERE username = :name");
    checkDataQuery.bindValue(":name", username);
    checkDataQuery.exec();

    if (checkDataQuery.next()) {
        QString hashFromDB = checkDataQuery.value(0).toString();
        QString saltFromDB = checkDataQuery.value(1).toString();
        userId = checkDataQuery.value(2).toInt();

        QByteArray bArrHash = QCryptographicHash::hash((password + saltFromDB).toUtf8(), QCryptographicHash::Sha256);
        QString hashedStr = bArrHash.toHex();

        if (hashedStr == hashFromDB) {
            idToName[userId] = username;
            idToSocket[userId] = client;
            socketToId[client] = userId;
            respCode = static_cast<int>(serverResponse::LoginOK);
            loginSuccessful = true;
        }
        else respCode = static_cast<int>(serverResponse::WrongPassword);
    }
    else respCode = static_cast<int>(serverResponse::UserNotFound);

    QByteArray response;
    if (loginSuccessful) {
        QString formatedMsg = QString("%1 %2 %3").arg(respCode).arg(userId).arg(username);
        response = formatedMsg.toUtf8();
    }
    else {
        response = QByteArray::number(respCode);
    }
    client->write(response);
}

void wServerClass::handleNameChange(QTcpSocket* client, QString msg) {
    int userId = socketToId[client];
    QString newUsername = std::move(msg);
    bool changeSuccessful = false;

    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", newUsername);
    checkQuery.exec();

    int respCode = -1;

    if (checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        QSqlQuery updateQuery;
        updateQuery.prepare("UPDATE users SET username = :newName WHERE id = :id");
        updateQuery.bindValue(":newName", newUsername);
        updateQuery.bindValue(":id", userId);
        updateQuery.exec(); 

        idToName[userId] = newUsername;
        respCode = static_cast<int>(serverResponse::Successful);
        changeSuccessful = true;
    }
    else respCode = static_cast<int>(serverResponse::UsernameExists);

    QByteArray response;
    if (changeSuccessful) {
        QString formatedMsg = QString("%1 %2").arg(respCode).arg(newUsername);
        response = formatedMsg.toUtf8();
    }
    else {
        response = QByteArray::number(respCode);
    } 
    client->write(response);
}

void wServerClass::handleChatMsg(QTcpSocket* client, QString msg) {
    int senderId = socketToId[client];
    int respCode = static_cast<int>(serverResponse::Message);
    QString msgForChat = std::move(msg);
    QString formatedMsg = QString("%1 %2 %3 %4").arg(respCode).arg(senderId).arg(idToName[senderId]).arg(msgForChat);

    for (auto cl : socketToId.keys()) {
        if (cl != client) cl->write(formatedMsg.toUtf8());
    }
}

void wServerClass::handlePrivateMsg(QTcpSocket* client, QString msg) {
    int recipientId = msg.section(' ', 0).toInt();
    int respCode = -1;

    if (!idToSocket.contains(recipientId)) {
        respCode = static_cast<int>(serverResponse::UserNotFound);
        client->write(QByteArray::number(respCode));
        return;
    }

    respCode = static_cast<int>(serverResponse::PrivateMessage);
    int senderId = socketToId[client];
    QString msgForUser = msg.section(' ', 1);
    QString formatedMsg = QString("%1 %2 %3 %4").arg(respCode).arg(senderId).arg(idToName[senderId]).arg(msgForUser);
    idToSocket[recipientId]->write(formatedMsg.toUtf8());
}

void wServerClass::handleLogout(QTcpSocket* client, QString msg) {
    client->disconnectFromHost();
}

QString wServerClass::generateSalt() {
    QByteArray salt(16, Qt::Uninitialized);
    QRandomGenerator::global()->generate(salt.begin(), salt.end());
    return salt.toHex();
}

wServerClass::~wServerClass()
{}

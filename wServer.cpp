#include "wServer.h"
#include <QCryptographicHash>

wServerClass::wServerClass(QWidget* parent)
    : QWidget(parent) {

        setupDB();
        setupServer();
        setupTimer();
        ui.setupUi(this);
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

void wServerClass::setupServer() {    
    server.listen(QHostAddress::LocalHost, 1402);
    connect(&server, &QTcpServer::newConnection, this, &wServerClass::onNewConnection);
}

void wServerClass::setupTimer() {
    updateOnlineNum = new QTimer(this);
    updateOnlineNum->setInterval(5000);
    updateOnlineNum->start();

    connect(updateOnlineNum, &QTimer::timeout, this, [this]() {
        ui.onlineField->setText(QString::number(socketToId.size()));
        });
}

void wServerClass::onNewConnection() {
    QTcpSocket* newClient = server.nextPendingConnection(); 
    int descr = newClient->socketDescriptor();
    connect(newClient, &QTcpSocket::readyRead, this, [this, newClient]() {
        processClientMsg(newClient);
        });

    connect(newClient, &QTcpSocket::disconnected, this, [this, newClient, descr]() {
        if (socketToId.contains(newClient)) {
            int userId = socketToId[newClient];
            ui.oField->append(QString("Клиент #%1 отключился").arg(descr));
            idToName.remove(userId);
            idToSocket.remove(userId);
            socketToId.remove(newClient);
            QTimer::singleShot(100, [this]() {
                sendOnlineList();
                });
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

    if (command != clientQuery::Logout) qLogger(client, command);

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

    int userId;
    bool regSuccessful = false;
    serverResponse resp;

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

        resp = serverResponse::Registered;
        regSuccessful = true;
    }
    else {
        resp = serverResponse::UsernameExists;
    }

    int respCode = static_cast<int>(resp);

    QByteArray response;
    if (regSuccessful) {
        QString formatedMsg = QString("%1 %2 %3").arg(respCode).arg(userId).arg(username);
        QTimer::singleShot(100, [this]() {
            sendOnlineList();
            });
        response = formatedMsg.toUtf8();
    }
    else {
        response = QByteArray::number(respCode);
    }

    rLogger(client, resp);
    client->write(response);
}

void wServerClass::handleLogin(QTcpSocket* client, QString msg) {
    QStringList msgParts = msg.split(' ');
    QString username = msgParts[0];
    QString password = msgParts[1];

    int userId;
    bool loginSuccessful = false;
    serverResponse resp;
    
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
            resp = serverResponse::LoginOK;
            loginSuccessful = true;
        }
        else resp = serverResponse::WrongPassword;
    }
    else resp = serverResponse::UserNotFound;

    int respCode = static_cast<int>(resp);

    QByteArray response;
    if (loginSuccessful) {
        QString formatedMsg = QString("%1 %2 %3").arg(respCode).arg(userId).arg(username);
        response = formatedMsg.toUtf8();
        QTimer::singleShot(100, [this]() {
            sendOnlineList();
            });
    }
    else {
        response = QByteArray::number(respCode);
    }

    rLogger(client, resp);
    client->write(response);
}

void wServerClass::handleNameChange(QTcpSocket* client, QString msg) {
    int userId = socketToId[client];
    QString newUsername = std::move(msg);
    bool changeSuccessful = false;
    serverResponse resp;

    if (newUsername.length() > 14) {
        client->write(QByteArray::number(static_cast<int>(serverResponse::NameTooLong)));
        return;
    }

    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", newUsername);
    checkQuery.exec();

    if (checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        QSqlQuery updateQuery;
        updateQuery.prepare("UPDATE users SET username = :newName WHERE id = :id");
        updateQuery.bindValue(":newName", newUsername);
        updateQuery.bindValue(":id", userId);
        updateQuery.exec(); 

        idToName[userId] = newUsername;
        resp = serverResponse::Successful;
        changeSuccessful = true;
    }
    else resp = serverResponse::UsernameExists;

    int respCode = static_cast<int>(resp);

    QByteArray response;
    if (changeSuccessful) {
        QString formatedMsg = QString("%1 %2").arg(respCode).arg(newUsername);
        response = formatedMsg.toUtf8();
    }
    else {
        response = QByteArray::number(respCode);
    } 

    rLogger(client, resp);
    client->write(response);
}

void wServerClass::handleChatMsg(QTcpSocket* client, QString msg) {
    int senderId = socketToId[client];
    int respCode = static_cast<int>(serverResponse::Message);
    QString msgForChat = std::move(msg);
    QString formatedMsg = QString("%1 %2 %3").arg(respCode).arg(idToName[senderId]).arg(msgForChat);

    for (auto cl : socketToId.keys()) {
        if (cl != client) cl->write(formatedMsg.toUtf8());

        rLogger(cl, serverResponse::Message);
    }
}

void wServerClass::handlePrivateMsg(QTcpSocket* client, QString msg) {
    int recipientId = msg.section(' ', 0).toInt();
    int respCode = -1;

    if (!idToSocket.contains(recipientId)) {
        respCode = static_cast<int>(serverResponse::UserNotFound);
        client->write(QByteArray::number(respCode));

        rLogger(client, serverResponse::UserNotFound);
        return;
    }

    respCode = static_cast<int>(serverResponse::PrivateMessage);
    int senderId = socketToId[client];
    QString msgForUser = msg.section(' ', 1);
    QString formatedMsg = QString("%1 %2 %3 %4").arg(respCode).arg(senderId).arg(idToName[senderId]).arg(msgForUser);
    idToSocket[recipientId]->write(formatedMsg.toUtf8());

    rLogger(idToSocket[recipientId], serverResponse::PrivateMessage);
}

void wServerClass::handleLogout(QTcpSocket* client, QString msg) {
    client->disconnectFromHost();
}

void wServerClass::sendOnlineList() {
    int respCode = static_cast<int>(serverResponse::UpdateOnline);
    QString response = QString::number(respCode);
    for (const auto& userId : idToName.keys()) {
        response += QString(" %1 %2").arg(userId).arg(idToName[userId]);
    }
    QByteArray bArrResp = response.toUtf8();
    for (QTcpSocket* client : socketToId.keys()) {
        client->write(bArrResp);
        rLogger(client, serverResponse::UpdateOnline);
    }
}

QString wServerClass::generateSalt() {
    QByteArray salt(16, Qt::Uninitialized);
    QRandomGenerator::global()->generate(salt.begin(), salt.end());
    return salt.toHex();
}

void wServerClass::qLogger(QTcpSocket* client, clientQuery query){
    QString text = QString("<font color='#821d8a'>[from: #%1]: %2</font>").arg(client->socketDescriptor()).arg(toStrQ(query));
    ui.oField->append(text);
}

void wServerClass::rLogger(QTcpSocket* client, serverResponse response) {
    QString text = QString("<font color='#ffa000'>[to: #%1]: %2</font>").arg(client->socketDescriptor()).arg(toStr(response));
    ui.oField->append(text);
}

wServerClass::~wServerClass() {
    server.close();
    for (auto client : socketToId.keys()) {
        client->disconnect();
    }
    socketToId.clear();
    idToSocket.clear();
    idToName.clear();
}

#include "wServer.h"
#include <QCryptographicHash>

wServerClass::wServerClass(QWidget* parent)
    : QWidget(parent) {

    ui.setupUi(this);
    setupDB();
    setupServer();
    setupTimers();
}

void wServerClass::setupDB() {

    QSettings settings("config.ini", QSettings::IniFormat);
    QString host = settings.value("DB/host").toString();
    int port = settings.value("DB/port").toInt();
    QString dbName = settings.value("DB/name").toString();
    QString user = settings.value("DB/user").toString();
    QString password = settings.value("DB/password").toString();

    chatDB = QSqlDatabase::addDatabase("QPSQL");
    chatDB.setHostName(host);
    chatDB.setPort(port);
    chatDB.setDatabaseName(dbName);
    chatDB.setUserName(user);
    chatDB.setPassword(password);

    if (!chatDB.open()) {
        ui.oField->append("Не удалось открыть БД");
        return;
    }

    QSqlQuery query;
    query.exec(
        "CREATE TABLE IF NOT EXISTS users ("
        "id SERIAL PRIMARY KEY NOT NULL, "
        "username TEXT UNIQUE, "
        "password TEXT,"
        "salt TEXT)"
    );
    query.exec(
        "CREATE TABLE IF NOT EXISTS history ("
        "id SERIAL PRIMARY KEY, "
        "senderId INTEGER NOT NULL, "
        "senderName TEXT, "
        "recipientId INTEGER, "
        "message TEXT)"
    );
}

void wServerClass::setupServer() {
    server.listen(QHostAddress::LocalHost, 1403);
    connect(&server, &QTcpServer::newConnection, this, &wServerClass::onNewConnection);
}

void wServerClass::setupTimers() {
    updateOnlineNum = new QTimer(this);
    updateOnlineNum->setInterval(5000);
    updateOnlineNum->start();

    connect(updateOnlineNum, &QTimer::timeout, this, [this]() {
        ui.onlineField->setText(QString::number(socketToId.size()));
        });

    const int day = 24 * 60 * 60 * 1000;
    cleanUpDB = new QTimer(this);
    cleanUpDB->setInterval(day);
    cleanUpDB->start();

    connect(cleanUpDB, &QTimer::timeout, this, [this]() {
        QSqlQuery query;
        query.exec("DELETE FROM history WHERE id < (SELECT id FROM history ORDER BY id DESC OFFSET 999 LIMIT 1)");
        });
}

void wServerClass::onNewConnection() {
    QTcpSocket* newClient = server.nextPendingConnection();
    auto* state = new clientState{0, true};
    int descr = newClient->socketDescriptor();

    connect(newClient, &QTcpSocket::readyRead, this, [this, state, newClient]() {
        while (true) {
            if (state->waitingForSize) {
                if (newClient->bytesAvailable() < 4) return;
                QByteArray sizeBytes = newClient->read(4);
                QDataStream stream(sizeBytes);
                stream >> state->sizeOfData;
                state->waitingForSize = false;
            }
            else {
                if (newClient->bytesAvailable() < state->sizeOfData) return;
                QByteArray data = newClient->read(state->sizeOfData);
                processClientMsg(newClient, data);
                state->waitingForSize = true;
            }
        }
        });

    connect(newClient, &QTcpSocket::disconnected, this, [this, state, newClient, descr]() {
        if (socketToId.contains(newClient)) {
            int userId = socketToId[newClient];
            ui.oField->append(QString("Клиент #%1 отключился").arg(descr));
            idToName.remove(userId);
            idToSocket.remove(userId);
            socketToId.remove(newClient);
            sendOnlineList();
        }
        delete state;
        newClient->deleteLater();
        });
}

void wServerClass::processClientMsg(QTcpSocket* client, const QByteArray& utf8msg) {
    QString strmsg = QString::fromUtf8(utf8msg);
    int code = strmsg.section(' ', 0, 0).toInt();
    QString textMsg = strmsg.section(' ', 1);
    clientQuery command = static_cast<clientQuery>(code);

    qLogger(client, command);

    switch (command)
    {
    case clientQuery::Register:
        handleRegistration(client, textMsg);
        break;
    case clientQuery::Login:
        handleLogin(client, textMsg);
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
    case clientQuery::GetHistory:
        sendHistory(client, textMsg);
        break;
    default:
        break;
    }
}

void wServerClass::handleRegistration(QTcpSocket* client, const QString& msg) {
    QStringList msgParts = msg.split('\n');
    QString username = msgParts[0];
    QString password = msgParts[1];

    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", username);
    checkQuery.exec();

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
        regSuccessful = true;
    }

    if (regSuccessful) {
        QString formatedMsg = QString("%1\n%2").arg(userId).arg(username);
        sendPacket(client, serverResponse::Registered, formatedMsg);
        sendOnlineList();
    }
    else sendPacket(client, serverResponse::UsernameExists);
}

void wServerClass::handleLogin(QTcpSocket* client, const QString& msg) {
    QStringList msgParts = msg.split('\n');
    QString username = msgParts[0];
    QString password = msgParts[1];

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
        if (idToSocket.contains(userId)) {
            sendPacket(client, serverResponse::AlreadyAuthorized);
            return;
        }

        QByteArray bArrHash = QCryptographicHash::hash((password + saltFromDB).toUtf8(), QCryptographicHash::Sha256);
        QString hashedStr = bArrHash.toHex();

        if (hashedStr == hashFromDB) {
            idToName[userId] = username;
            idToSocket[userId] = client;
            socketToId[client] = userId;
            loginSuccessful = true;
        }
    }
    else {
        sendPacket(client, serverResponse::UserNotFound);
        return;
    }

    QString formatedMsg;

    if (loginSuccessful) {
        formatedMsg = QString("%1\n%2").arg(userId).arg(username);
        sendPacket(client, serverResponse::LoginOK, formatedMsg);
        sendOnlineList();
    }
    else sendPacket(client, serverResponse::WrongPassword);
}

void wServerClass::handleNameChange(QTcpSocket* client, QString& msg) {
    int userId = socketToId[client];
    QString formatedMsg;
    QString newUsername = msg;

    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT COUNT(username) FROM users WHERE username = :name");
    checkQuery.bindValue(":name", newUsername);
    checkQuery.exec();

    bool changeSuccessful = false;
    if (checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        QSqlQuery updateQuery;
        updateQuery.prepare("UPDATE users SET username = :newName WHERE id = :id");
        updateQuery.bindValue(":newName", newUsername);
        updateQuery.bindValue(":id", userId);
        updateQuery.exec();

        idToName[userId] = newUsername;
        changeSuccessful = true;
    }

    if (changeSuccessful) {
        sendPacket(client, serverResponse::Successful, newUsername);
        sendOnlineList();
    }
    else sendPacket(client, serverResponse::UsernameExists);
}

void wServerClass::handleChatMsg(QTcpSocket* client, const QString& msg) {
    int senderId = socketToId[client];
    QString formatedMsg = QString("%1\n%2").arg(idToName[senderId]).arg(msg);

    for (auto cl : socketToId.keys()) {
        if (cl == client) continue;
        sendPacket(cl, serverResponse::Message, formatedMsg);
    }
    saveToDB(senderId, idToName[senderId], 0, msg);
}

void wServerClass::handlePrivateMsg(QTcpSocket* client, const QString& msg) {
    int recipientId = msg.section('\n', 0, 0).toInt();
    int senderId = socketToId[client];
    QString msgForUser = msg.section('\n', 1);
    QString formatedMsg = QString("%1\n%2\n%3").arg(senderId).arg(idToName[senderId]).arg(msgForUser);

    if (idToSocket.contains(recipientId)) {
        sendPacket(idToSocket[recipientId], serverResponse::PrivateMessage, formatedMsg);
    }
    saveToDB(senderId, idToName[senderId], recipientId, msgForUser);
}

void wServerClass::sendOnlineList() {
    QStringList list;
    for (const auto& userId : idToName.keys()) {
        list << QString("%1\n%2").arg(userId).arg(idToName[userId]);
    }
    QString response = list.join("\n\n");

    for (QTcpSocket* client : socketToId.keys()) {
        sendPacket(client, serverResponse::UpdateOnline, response);
    }
}

void wServerClass::sendPacket(QTcpSocket* client, const serverResponse response, const QString& data) {
    int respCode = static_cast<int>(response);
    QString formatedData = data.isEmpty() ? QString::number(respCode) : QString("%1 %2").arg(respCode).arg(data);
    QByteArray bArrData = formatedData.toUtf8();
    qint32 dataSize = bArrData.size();

    QByteArray packet;
    QDataStream stream(&packet, QIODeviceBase::WriteOnly);
    stream << dataSize;
    packet += bArrData;
    client->write(packet);
    rLogger(client, response);
}

void wServerClass::sendHistory(QTcpSocket* client, const QString& msg) {
    int otherId = msg.toInt();
    QSqlQuery query;
    if (otherId != 0) {
        query.prepare(
            "SELECT senderId, senderName, message FROM history "
            "WHERE (senderId = :sender AND recipientId = :recipient) "
            "OR (senderId = :recipient AND recipientId = :sender) "
            "ORDER BY id"
        );
        query.bindValue(":sender", socketToId[client]);
        query.bindValue(":recipient", otherId);
        query.exec();

    }
    else {
        query.exec(
            "SELECT senderId, senderName, message FROM history "
            "WHERE recipientId = 0 "
            "ORDER BY id"
        );
    }

    QStringList list;
    QString senderId;
    QString senderName;
    QString message;
    while (query.next()) {
        senderId = query.value(0).toString();
        senderName = query.value(1).toString();
        message = query.value(2).toString();
        list << QString("%1\n%2\n%3").arg(senderId).arg(senderName).arg(message);
    }

    QString response = QString("%1\n%2").arg(otherId).arg(list.join("\n\n"));
    sendPacket(client, serverResponse::SendHistory, response);
}

void wServerClass::saveToDB(const int senderId, const QString& senderName, const int recipientId, const QString& msg) {
    QSqlQuery query;
    query.prepare("INSERT INTO history (senderId, senderName, recipientId, message) VALUES (:sId, :sName, :rId, :msg)");
    query.bindValue(":sId", senderId);
    query.bindValue(":sName", senderName);
    query.bindValue(":rId", recipientId);
    query.bindValue(":msg", msg);
    query.exec();
}

QString wServerClass::generateSalt() {
    QByteArray salt(16, Qt::Uninitialized);
    QRandomGenerator::global()->generate(salt.begin(), salt.end());
    return salt.toHex();
}

void wServerClass::qLogger(QTcpSocket* client, clientQuery query) {
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
}


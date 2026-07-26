# OnlineChat
Многопользовательский онлайн-чат. C++17, Qt 6 (widgets, network, sql).

Серверная часть:
  - безопасное хранение паролей
  - одновременная обработка подключений
  - отображение количества онлайн-пользователей
  - автоматическая очистка истории сообщений раз в день если количество в БД превышает порог
  - кастомный протокол с бинарным префиксом размера

1. Асинхронный TCP-сервер
  ```cpp
  QTcpServer server;  // Слушает входящие подключения
  QHash<QTcpSocket*, int> socketToId; // сокет -> ID пользователя
  QHash<int, QTcpSocket*> idToSocket; // ID пользователя -> сокет
  QHash<int, QString> idToName; // ID пользователя -> имя
  ```

2. База данных PostgeSQL/SQLite
    - в таблице users хранятся данные пользователей
    - в таблице history хранится архив сообщений
    - запросы к БД с защитой от SQL-инъекций

3. Безопасность
    - при регистрации генерируется соль, добавляется к паролю пользователя, полученная строка хэшируется SHA-256:
  ```cpp
  QString wServerClass::generateSalt() {
      QByteArray salt(16, Qt::Uninitialized);
      QRandomGenerator::global()->generate(salt.begin(), salt.end());
      return salt.toHex();
  }
  ```
  ```cpp
  QString salt = generateSalt(); 
  QString strToHash = password + salt;
  QByteArray bArrHashedStr = QCryptographicHash::hash(strToHash.toUtf8(), QCryptographicHash::Sha256);
  ```
4. Протокол
    - пакет имеет формат `[4 байта - размер данных][данные - код ответа и информация]`
    - коды запросов (clientQuery) и коды ответов (serverResponse) содержатся в общем файле protocol.h

5. Обмен пакетами
    - формирование пакета:
  ```cpp
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
}
```
  - получение пакета от клиента: 
```cpp
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
```
  - последующая обработка в switch с разбиением по типу запроса:
```cpp
        switch (command)
    {
    case clientQuery::Register:
        handleRegistration(client, textMsg);
        break;
    case clientQuery::Login:
        handleLogin(client, textMsg);
        break;
    ...
```
  - история рассылается при авторизации и открытии вкладки личных сообщений (по запросу клиента)
  - список онлайна рассылается при входе и выходе

Cборка с SQLite под Windows: [https://github.com/L3n44nd/OnlineChatServer/releases/download/v1.1.0/ServerSQLite.zip]

Сборка с PostgreSQL [https://github.com/L3n44nd/OnlineChatServer/releases/download/v1.1.1/ServerPostgreSQL.zip]

Для PostgreSQL в файле конфигурации `config.ini` прописать:  
```
[DB]
host=localhost
port=(кроме 1403)
name=(имя БД)
user=(имя пользователя)
password=(пароль)
```


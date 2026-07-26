#pragma once

#ifndef PROTOCOL_H
#define PROTOCOL_H

enum class clientQuery {
	Register,
	Login,
	Message,
	PrivateMessage,
	NameChange,
	GetHistory
};

enum class serverResponse {
	Successful,
	Registered, 
	LoginOK,
	WrongPassword,
	UserNotFound,
	UsernameExists,
	Message, 
	PrivateMessage, 
	UpdateOnline,
	SendHistory,
	AlreadyAuthorized
};

inline const char* toStr(serverResponse resp) {
	switch (resp) {
	case serverResponse::Successful: return "Имя изменено";
	case serverResponse::Registered: return "Регистрация успешна";
	case serverResponse::LoginOK: return "Вход выполнен";
	case serverResponse::WrongPassword: return "Неверный пароль";
	case serverResponse::UserNotFound: return "Пользователь не найден";
	case serverResponse::UsernameExists: return "Имя занято";
	case serverResponse::UpdateOnline: return "Обновление онлайна";
	case serverResponse::PrivateMessage: return "Личное сообщение";
	case serverResponse::Message: return "Сообщение";
	case serverResponse::SendHistory: return "История";
	case serverResponse::AlreadyAuthorized: return "Пользователь уже авторизован";
	default: return "Неизвестный код ответа";
	}
}

inline const char* toStrQ(clientQuery query) {
	switch (query)
	{
	case clientQuery::Register: return "Регистрация";
	case clientQuery::Login: return "Авторизация";
	case clientQuery::Message: return "Сообщение";
	case clientQuery::PrivateMessage: return "Личное сообщение";
	case clientQuery::NameChange: return "Смена имени";
	case clientQuery::GetHistory: return "Запрос истории";
	default: return "Неизвестный код запроса";
	}
}
#endif // !PROTOCOL_H

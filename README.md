# go_task
 Четыре REST маршрута:
• Первый маршрут выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса
• Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов
• Третий маршрут удаляет конкретный Refresh токен из базы
• Четвертый маршрут удаляет все Refresh токены из базы для конкретного пользователя

Язык программирования Go.
База данных MongoDB, использование транзакций.
Access токен тип JWT, алгоритм SH512.
Refresh токен тип JWT, формат передачи base64, хранится в базе в виде bcrypt хеша, защищен от изменения на стороне клиента и попыток повторного использования.
Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

# AuthJWT

В пакете routes описаны 3 маршрута:<br/>
- "/users/signup" - регистрация пользователей<br/>
- "/users/login" - выдает пару Access, Refresh токенов для пользователя<br/>
- "/users/refresh" - выполняет Refresh операцию на пару Access, Refresh токенов<br/>

Пакет controllers содержит обработчики rest маршрутов<br/>
Пакет middleware служит для промежуточной проверки токенов при выполнении запросов к API<br/>
Пакет database служит для подключения к БД<br/>
Пакет models содержит структуру пользовательской модели<br/>
Пакет helpers содержит вспомогательные функции для проверки токенов, генерации ключей и создания hash<br/>
<br/>
Для тестирования использовал Postman. Экспортировал запросы из postman в файл Ver2.postman_collection.json <br/>

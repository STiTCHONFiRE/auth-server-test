# Тестовый провайдер аутентификации

Провайдер аутентификации, работающий по стандарту `OpenID Connect 1.0`.

Минимальная версия Java: `20`.

## Конфигурация

Настройка адреса провайдера и адреса клиента в `application.yml`:

```yaml
config:
  issuer-uri: http://localhost:9000
  redirect-uri: http://localhost:4200
```

Настройка аккаунта администратора:

```yaml
users:
  admin:
    username: admin
    password: test
```

Настройка для подключения к базе данных:

```yaml
spring:
  application:
    name: auth-server
  datasource:
    password: password
    url: jdbc:postgresql://localhost:5432/auth
    username: root
  jpa:
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
      show-sql: true
```

В тестовом сервере на данный момент нет миграции базы данных, из-за чего используется автоматические средства `Hibernate`. В базе данных сохраняются данные о пользователях.

Настройка порта сервера и название `cookie` авторизации.

```yaml
server:
  servlet:
    session:
      cookie:
        name: AUTH_JSESSIONID
  port: 9000
```

## Сборка

Для сборки можно использовать `maven wrapper` или установить maven.

`maven wrapper`:

```shell
./mvnw package
```

`maven`:

```shell
mvn package
```
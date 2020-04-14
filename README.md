# The Authenticatiion server for Tusla PoC

## Locally
To run this service locally with maven command 

```
mvn spring-boot:run
```

## PCF
To build and push to Cloud Foundry you run the following command.
```
mvn clean package && cf push
```
This assumes you've set the correct Cloud Foundry environment beforehand.

## Getting JWT token
This server generates JWT token which will be used for authentication
and authorization against all microservices.

In order to get the token from postman or any rest clients, you can configure basic authetication with parameters:  
```
username:eik
password:Tusla2018
```
and in the body of form data you have to add parameters:
```
grant_type:password
scope:webclient
username:<your name>
password:<your password>
```

Existing user name and password(same as username) with USER access are:
aniket, samrat,ashwini ,antima,levent,jonathan,waqar,ravi having USER role 

and henric having USER and ADMIN role


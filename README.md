# OAuth 2.0 intergated with Keycloak library
This project have the code for OAuth 2.0 access JWT Token validation with Spring Security. Keycloak Server is use as authorization server and in short is responsible of issuing an access token.<br/>
So every microservice need to validate access token, by using this lib as jar depencency, we just need to set SecurityConfig.java file for more refernce please see the movie application project.     

### Valid Access Token 
Valid Access Token have following items (https://jwt.io/) :- <br/>
* JWT token. <br/>
* Signature. <br/> 
* Token is not expired. <br/>
* Contains roles and scopes information. <br/>

### Jfrog repository jar link 
https://nitinraidev.jfrog.io/ui/native/nitin-gradle-dev/com/nitin/oauth2/lib/OAuth2KeycloakLib/0.0.1-SNAPSHOT/

### Build the jar command
```
    gradlew clean build 

```

### Publish the Artifactory 
For publish the jar into the Artifactory, you need to setup jfrog cloud artifactory and provide the credential in the gradle.properties file.(https://jfrog.com/start-free/) <br/>

```
    gradlew artifactorypublish

```



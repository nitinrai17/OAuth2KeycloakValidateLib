package com.nitin.oauth2.OAuth2Keycloak.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidTokenException extends AuthenticationException{

	public InvalidTokenException(String message) {
		 super(message);
	}
	
	public InvalidTokenException(String message, Throwable cause) {
		super(message,cause);
	}
}

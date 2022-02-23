package com.nitin.oauth2.oauth2keycloak.exception;

public class CustomInvalidTokenException extends Exception {

	public CustomInvalidTokenException(String message) {
		 super(message);
	}
	
	public CustomInvalidTokenException(String message, Throwable cause) {
		super(message,cause);
	}
}

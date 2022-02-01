package com.nitin.oauth2.OAuth2Keycloak.security;

import java.io.IOException;
import java.time.Instant;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class AuthorizationAccessDeniedHandler implements AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {

		response.setStatus(HttpStatus.FORBIDDEN.value());
		response.setContentType("applications/json;charset=UTF-8");
		response.getWriter().write(createErrorBody(accessDeniedException));

	}

	private String createErrorBody(AccessDeniedException accessDeniedException) {

		JsonObject exceptionMessage = new JsonObject();
		exceptionMessage.addProperty("code", HttpStatus.FORBIDDEN.value());
		exceptionMessage.addProperty("reason", HttpStatus.FORBIDDEN.value());
		exceptionMessage.addProperty("timestamp", Instant.now().toString());
		exceptionMessage.addProperty("message", accessDeniedException.getMessage());
		return new Gson().toJson(exceptionMessage);
	}
}

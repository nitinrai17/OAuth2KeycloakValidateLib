package com.nitin.oauth2.OAuth2Keycloak.security;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nitin.oauth2.OAuth2Keycloak.security.utils.SecurityUtils;


public class AccessToken {

	private final String value;
	
	public AccessToken(String token) {
		this.value=token;
	}

	public String getValueAsString() {
		return value;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		JsonObject payloadAsJson = getPayloadAsJsonObject();

		return StreamSupport
				.stream(payloadAsJson.getAsJsonObject("realm_access").getAsJsonArray("roles").spliterator(), false)
				.map(JsonElement::getAsString).map(SimpleGrantedAuthority::new).collect(Collectors.toList());

	}

	public String getUsername() {
		JsonObject payloadAsJson = getPayloadAsJsonObject();
		return Optional.ofNullable(payloadAsJson.getAsJsonPrimitive("preferred_username").getAsString()).orElse("");
	}

	private JsonObject getPayloadAsJsonObject() {
		DecodedJWT decodedJWT = SecurityUtils.decodeToken(value);
		return SecurityUtils.decodeTokenPayloadToJsonObject(decodedJWT);
	}

}

package com.nitin.oauth2.OAuth2Keycloak.security.utils;

import static java.util.Objects.isNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.nitin.oauth2.OAuth2Keycloak.exception.InvalidTokenException;

public class SecurityUtils {
	
	
	public static JsonObject decodeTokenPayloadToJsonObject(DecodedJWT decodedJWT) {
        try {
            String payloadAsString = decodedJWT.getPayload();
            return new Gson().fromJson(
                    new String(Base64.getDecoder().decode(payloadAsString), StandardCharsets.UTF_8),
                    JsonObject.class);
        }   catch (RuntimeException exception){
            throw new InvalidTokenException("Invalid JWT or JSON format of each of the jwt parts", exception);
        }
    }
	
	public static DecodedJWT decodeToken(String value) {
		if (isNull(value)) {
			throw new InvalidTokenException("Token has not been provided");
		}
		return JWT.decode(value);
	}

}

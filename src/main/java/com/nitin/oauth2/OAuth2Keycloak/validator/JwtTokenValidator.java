package com.nitin.oauth2.OAuth2Keycloak.validator;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Preconditions;
import com.google.gson.JsonObject;
import com.nitin.oauth2.OAuth2Keycloak.exception.CustomInvalidTokenException;
import com.nitin.oauth2.OAuth2Keycloak.security.AccessToken;
import com.nitin.oauth2.OAuth2Keycloak.security.utils.SecurityUtils;

public class JwtTokenValidator {

	private final JwkProvider jwkProvider;
	
	public static final String BEARER = "Bearer ";
	
	private final Logger log = LoggerFactory.getLogger(JwtTokenValidator.class);
	
	public JwtTokenValidator(JwkProvider jwkProvider) {
		this.jwkProvider=jwkProvider;
	}

	public AccessToken validateAuthorizationHeader(String authorizationHeader) throws CustomInvalidTokenException {
		log.debug(" authorizationHeader ="+authorizationHeader);
		String tokenValue = subStringBearer(authorizationHeader);
		validateToken(tokenValue);
		return new AccessToken(tokenValue);
	}

	private void validateToken(String value) throws CustomInvalidTokenException {
		DecodedJWT decodedJWT = SecurityUtils.decodeToken(value);
		verifyTokenHeader(decodedJWT);
		verifySignature(decodedJWT);
		verifyPayload(decodedJWT);
	}

	private void verifyTokenHeader(DecodedJWT decodedJWT) throws CustomInvalidTokenException {
		try {
			Preconditions.checkArgument(decodedJWT.getType().equals("JWT"));
			log.debug("Token's header is correct");
		} catch (IllegalArgumentException ex) {
			throw new CustomInvalidTokenException("Token is not JWT type", ex);
		}
	}

	private void verifySignature(DecodedJWT decodedJWT) throws CustomInvalidTokenException {
		try {
			Jwk jwk = jwkProvider.get(decodedJWT.getKeyId());
			Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
			algorithm.verify(decodedJWT);
			log.debug("Token's signature is correct");
		} catch (JwkException | SignatureVerificationException ex) {
			throw new CustomInvalidTokenException("Token has invalid signature", ex);
		}
	}

	private void verifyPayload(DecodedJWT decodedJWT) throws CustomInvalidTokenException {
		JsonObject payloadAsJson = SecurityUtils.decodeTokenPayloadToJsonObject(decodedJWT);
		if (hasTokenExpired(payloadAsJson)) {
			throw new CustomInvalidTokenException("Token has expired");
		}
		log.debug("Token has not expired");

		if (!hasTokenRealmRolesClaim(payloadAsJson)) {
			throw new CustomInvalidTokenException("Token doesn't contain claims with realm roles");
		}
		log.debug("Token's payload contain claims with realm roles");

		if (!hasTokenScopeInfo(payloadAsJson)) {
			throw new CustomInvalidTokenException("Token doesn't contain scope information");
		}
		log.debug("Token's payload contain scope information");
	}

	boolean hasTokenExpired(JsonObject payloadAsJson) throws CustomInvalidTokenException {
		Instant expirationDatetime = extractExpirationDate(payloadAsJson);
		return Instant.now().isAfter(expirationDatetime);
	}

	private Instant extractExpirationDate(JsonObject payloadAsJson) throws CustomInvalidTokenException {
		try {
			return Instant.ofEpochSecond(payloadAsJson.get("exp").getAsLong());
		} catch (NullPointerException ex) {
			throw new CustomInvalidTokenException("There is no 'exp' claim in the token payload");
		}
	}

	private boolean hasTokenRealmRolesClaim(JsonObject payloadAsJson) {
		try {
			return payloadAsJson.getAsJsonObject("realm_access").getAsJsonArray("roles").size() > 0;
		} catch (NullPointerException ex) {
			return false;
		}
	}

	private boolean hasTokenScopeInfo(JsonObject payloadAsJson) {
		return payloadAsJson.has("scope");
	}

	private String subStringBearer(String authorizationHeader) throws CustomInvalidTokenException {
		try {
			return authorizationHeader.substring(BEARER.length());
		} catch (Exception ex) {
			throw new CustomInvalidTokenException("There is no AccessToken in a request header");
		}
	}
}

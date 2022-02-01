package com.nitin.oauth2.OAuth2Keycloak.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.google.gson.JsonObject;
import com.nitin.oauth2.OAuth2Keycloak.exception.InvalidTokenException;
import com.nitin.oauth2.OAuth2Keycloak.security.AccessToken;

@ExtendWith(MockitoExtension.class)
class JwtTokenValidatorTest {
	
	private String token="Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJyQVRmMHBFdXM1eTJOV1VjR3lyUG04ZUd2cExZbkN6anl3aFY4ZHlaSWRJIn0.eyJleHAiOjE2NDI2MTMzNjMsImlhdCI6MTY0MjYxMzA2MywianRpIjoiNjk0ZmFmMjItN2M1Yi00N2EyLWFmNTYtYjAwZjFjMmU3NjU1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL3Rlc3QiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2I4MDliODktNjc2ZS00MTEwLTg4ZTYtZjY4ZDQ5YWJlYWExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdF9jbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiMTRhOGUwN2EtY2QyMS00YzBkLTg1NWQtY2ExMmVjMjhhY2Y5IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLXRlc3QiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiQURNSU4iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiMTRhOGUwN2EtY2QyMS00YzBkLTg1NWQtY2ExMmVjMjhhY2Y5IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiTml0aW4gUmFpIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibml0aW4iLCJnaXZlbl9uYW1lIjoiTml0aW4iLCJmYW1pbHlfbmFtZSI6IlJhaSIsImVtYWlsIjoibml0aW5yYWkxN0BnbWFpbC5jb20ifQ.kBs5z1xvNIA38METwVThkqB73LibOaaUE7H0twQn0Ki41WLGyoZmBfNBYdgbl3NZJG0jCVe3npkculRoX0lSI4HdKqsJw2F1TfO41nDOibyG3mU2gcmQqrC6hS3VNdnQmIXy2g1LlRg-Y3fTqh4yBN565lkur31UavpTDYrXPzm3nFSAo6NPRu9xhzsyGQD16Qd9Rs-_YdT34p5LLJVJlBpvP-JSlasKU2dzszXbkurDuwwBb3huzl0EsacOBAxeyvq8wBUsoQV0UlA38Hy8vsGWA9RiTUiYioF0CMxSQD4s89TS6SYIS9p4Lxt2oypqOxoQPIWPATidu1-C-xexOA";
	
	private Map<String,Object> jwkMap= Map.of(
			"kid","rATf0pEus5y2NWUcGyrPm8eGvpLYnCzjywhV8dyZIdI",
			"kty","RSA",
			"alg","RS256", 
			"use","sig",
			"n","0wO3ESDPOt4ywydiPFsp3iJbOU4TgPSu_5iZkDe1-7yP-7fmtn4QlE3PxJb167g0FZ0ROrYkCTT9PdWwQHqnSfxB95akim7NKZnIullzQuALDuCJH6yThlw6csuEfMV4pu9ymm5mtCux5MUhtq3SVfQIWNjti5m2hEuwIVvu96cdNeCq3GcKtXtj7O-aOn4lQjthteiqaIFo70-mnMIXjQLc6xtGg7K-8g-H_vO5a6mNBsVv_72BQ71IPZcRlhRr0hO52PjmKHUqvkFMscnXHSFkmyczRJpSYdZXjRQwg_Jjpmiz9V5wjrtEf7TTwsUJP0JgWK8CTbm9qm6SNH26Bw",
			"e","AQAB",
			"x5c",Arrays.asList("MIIClzCCAX8CBgF+WdqX4TANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR0ZXN0MB4XDTIyMDExNDE4MjgyNVoXDTMyMDExNDE4MzAwNVowDzENMAsGA1UEAwwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANMDtxEgzzreMsMnYjxbKd4iWzlOE4D0rv+YmZA3tfu8j/u35rZ+EJRNz8SW9eu4NBWdETq2JAk0/T3VsEB6p0n8QfeWpIpuzSmZyLpZc0LgCw7giR+sk4ZcOnLLhHzFeKbvcppuZrQrseTFIbat0lX0CFjY7YuZtoRLsCFb7venHTXgqtxnCrV7Y+zvmjp+JUI7YbXoqmiBaO9PppzCF40C3OsbRoOyvvIPh/7zuWupjQbFb/+9gUO9SD2XEZYUa9ITudj45ih1Kr5BTLHJ1x0hZJsnM0SaUmHWV40UMIPyY6Zos/VecI67RH+008LFCT9CYFivAk25vapukjR9ugcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAIejVk9Mpl0We2fo9ZtuFREvj4Lpf2T4OlnwNOjXcujhBaQty4C9nBxz0dsMF7LeokYeZsHnw5zVjrbzoZtbNWlf+k6ty2jPRB/JQoPsHgfHza1FMLe8hoC4qj9tTt0meGKsRzzDJaO67LKhX7I57vER7S9rtIm3/5/YR8iMj6fuC9Ba/7/TxU8unolFWBEA8elrKDimHfnVyrlq0gvrPmPT0gp9MWD12GxRQ/po0zLQppywaFB1Uzdg8iV1gcrC+7VJNOvZLEXdWnAXxCwZt9lQ4OmhrFS6Z7VzUdh1djdhnxYcL1+z01aA/hnWePiPq3hA44rFGk2xKwPDIaQ/sgw=="),
			"x5t","acIouugbnE1hK6ajlFAGnpUcxNc",
			"x5t#S256","iHQRaZ37X_EVzDulPahChfyOtaYCO9hpRcerGSu2UvA"
			);

	@Mock
	private JwkProvider jwkProvider = new KeycloakJwkProvider("http://localhost:8080/");

	@Test 
	void testValidateAuthorizationHeader_Success_Scenario() throws JwkException {
		//given 
		JwtTokenValidator jwtTokenValidator = new JwtTokenValidator(jwkProvider) {
			boolean hasTokenExpired(JsonObject payloadAsJson) {
				return false;
			}
		};

		Jwk jwk= Jwk.fromValues(jwkMap);
		
		//when
		when(jwkProvider.get(anyString())).thenReturn(jwk);
		
		AccessToken accessToken  = jwtTokenValidator.validateAuthorizationHeader(token);
		//then
		assertNotNull(accessToken);
		assertEquals("nitin", accessToken.getUsername());
		assertEquals(token.substring(7), accessToken.getValueAsString());
		assertEquals("[default-roles-test, offline_access, uma_authorization, ADMIN]", accessToken.getAuthorities().toString());
	}
	
	@Test 
	void testValidateAuthorizationHeaderFailure_Invalid_Signature() throws JwkException {
		//given
		String invalid_Signature_token="Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJyQVRmMHBFdXM1eTJOV1VjR3lyUG04ZUd2cExZbkN6anl3aFY4ZHlaSWRJIn0.eyJleHAiOjE2NDI2MTMzNjMsImlhdCI6MTY0MjYxMzA2MywianRpIjoiNjk0ZmFmMjItN2M1Yi00N2EyLWFmNTYtYjAwZjFjMmU3NjU1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL3Rlc3QiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2I4MDliODktNjc2ZS00MTEwLTg4ZTYtZjY4ZDQ5YWJlYWExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdF9jbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiMTRhOGUwN2EtY2QyMS00YzBkLTg1NWQtY2ExMmVjMjhhY2Y5IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLXRlc3QiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiQURNSU4iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiMTRhOGUwN2EtY2QyMS00YzBkLTg1NWQtY2ExMmVjMjhhY2Y5IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiTml0aW4gUmFpIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibml0aW4iLCJnaXZlbl9uYW1lIjoiTml0aW4iLCJmYW1pbHlfbmFtZSI6IlJhaSIsImVtYWlsIjoibml0aW5yYWkxN0BnbWFpbC5jb20ifQ.kBs5z1xvNIA38METwVThkqB73LibOaaUE7H0twQn0Ki41WLGyoZmBfNBYdgbl3NZJG0jCVe3npkculRoX0lSI4HdKqsJw2F1TfO41nDOibyG3mU2gcmQqrC6hS3VNdnQmIXy2g1LlRg-Y3fTqh4yBN565lkur31UavpTDYrXPzm3nFSAo6NPRu9xhzsyGQD16Qd9Rs-_YdT34p5LLJVJlBpvP-JSlasKU2dzszXbkurDuwwBb3huzl0EsacOBAxeyvq8wBUsoQV0UlA38Hy8vsGWA9RiTUiYioF0CMxSQD4s89TS6SYIS9p4Lxt2oypqOxoQPIWPATidu1-C-xexO";
		JwtTokenValidator jwtTokenValidator = new JwtTokenValidator(jwkProvider) ;
		Jwk jwk= Jwk.fromValues(jwkMap);
		
		//when
		when(jwkProvider.get(anyString())).thenReturn(jwk);
		
		//then
		InvalidTokenException invalidTokenException =assertThrows(InvalidTokenException.class,()->{jwtTokenValidator.validateAuthorizationHeader(invalid_Signature_token); });
		assertEquals("Token has invalid signature", invalidTokenException.getMessage());
	}
	
	@Test 
	void testValidateAuthorizationHeaderFailure_Token_Expired() throws JwkException {
		//given
		JwtTokenValidator jwtTokenValidator = new JwtTokenValidator(jwkProvider) ;
		Jwk jwk= Jwk.fromValues(jwkMap);
		
		//when
		when(jwkProvider.get(anyString())).thenReturn(jwk);
		
		//then
		InvalidTokenException invalidTokenException = assertThrows(InvalidTokenException.class,()->{jwtTokenValidator.validateAuthorizationHeader(token); });
		assertEquals("Token has expired", invalidTokenException.getMessage());
	}
	

}

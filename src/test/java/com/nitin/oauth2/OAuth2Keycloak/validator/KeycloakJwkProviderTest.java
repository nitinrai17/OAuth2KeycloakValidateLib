package com.nitin.oauth2.OAuth2Keycloak.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.SigningKeyNotFoundException;
import com.nitin.oauth2.OAuth2Keycloak.exception.InvalidTokenException;

@ExtendWith(MockitoExtension.class)
class KeycloakJwkProviderTest {
	
	private String keyId ="rATf0pEus5y2NWUcGyrPm8eGvpLYnCzjywhV8dyZIdI";
	
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
	
	
	private List<Map<String,Object>> list = Arrays.asList(jwkMap);
	
	private Map<String,Object> mapResponse= Map.of("keys",list);
	

	@Test
	void testGet_Success_Scenario() throws Exception {
		//given
		KeycloakJwkProvider provider = new KeycloakJwkProvider("http://localhost:8080") {
			Map<String, Object> getJwks() throws SigningKeyNotFoundException {
				return mapResponse;
			}
		};
		
		Jwk jwk = provider.get(keyId);
		//then
		assertNotNull(jwk);
		assertEquals(jwk.getId(), jwkMap.get("kid"));
		assertEquals(jwk.getType(), jwkMap.get("kty"));
		assertEquals(jwk.getAlgorithm(), jwkMap.get("alg"));
		assertEquals(jwk.getUsage(), jwkMap.get("use"));
		assertEquals(jwk.getCertificateChain(), jwkMap.get("x5c"));
		assertEquals(jwk.getCertificateThumbprint(), jwkMap.get("x5t"));
	}
	
	@Test
	void testGet_Fail_Scenario() throws Exception {
		//given
		KeycloakJwkProvider provider = new KeycloakJwkProvider("http://localhost:8080") {
			Map<String, Object> getJwks() throws SigningKeyNotFoundException {
				return Map.of("keys", Arrays.asList()) ;
			}
		};
		//then
		SigningKeyNotFoundException signingKeyNotFoundException =assertThrows(SigningKeyNotFoundException.class,()->{provider.get(keyId);});
		assertEquals("No keys found in http://localhost:8080", signingKeyNotFoundException.getMessage());
	}

}

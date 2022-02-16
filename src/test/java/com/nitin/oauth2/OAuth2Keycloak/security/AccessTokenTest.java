package com.nitin.oauth2.OAuth2Keycloak.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nitin.oauth2.OAuth2Keycloak.exception.CustomInvalidTokenException;

@ExtendWith(MockitoExtension.class)
class AccessTokenTest {

	private String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJyQVRmMHBFdXM1eTJOV1VjR3lyUG04ZUd2cExZbkN6anl3aFY4ZHlaSWRJIn0.eyJleHAiOjE2NDI2MTMzNjMsImlhdCI6MTY0MjYxMzA2MywianRpIjoiNjk0ZmFmMjItN2M1Yi00N2EyLWFmNTYtYjAwZjFjMmU3NjU1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL3Rlc3QiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2I4MDliODktNjc2ZS00MTEwLTg4ZTYtZjY4ZDQ5YWJlYWExIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdF9jbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiMTRhOGUwN2EtY2QyMS00YzBkLTg1NWQtY2ExMmVjMjhhY2Y5IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLXRlc3QiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiQURNSU4iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiMTRhOGUwN2EtY2QyMS00YzBkLTg1NWQtY2ExMmVjMjhhY2Y5IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiTml0aW4gUmFpIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibml0aW4iLCJnaXZlbl9uYW1lIjoiTml0aW4iLCJmYW1pbHlfbmFtZSI6IlJhaSIsImVtYWlsIjoibml0aW5yYWkxN0BnbWFpbC5jb20ifQ.kBs5z1xvNIA38METwVThkqB73LibOaaUE7H0twQn0Ki41WLGyoZmBfNBYdgbl3NZJG0jCVe3npkculRoX0lSI4HdKqsJw2F1TfO41nDOibyG3mU2gcmQqrC6hS3VNdnQmIXy2g1LlRg-Y3fTqh4yBN565lkur31UavpTDYrXPzm3nFSAo6NPRu9xhzsyGQD16Qd9Rs-_YdT34p5LLJVJlBpvP-JSlasKU2dzszXbkurDuwwBb3huzl0EsacOBAxeyvq8wBUsoQV0UlA38Hy8vsGWA9RiTUiYioF0CMxSQD4s89TS6SYIS9p4Lxt2oypqOxoQPIWPATidu1-C-xexOA";

	AccessToken accessToken = new AccessToken(token);

	@Test
	void testGetAuthorities() throws CustomInvalidTokenException {
		Collection<?> authorities = accessToken.getAuthorities();

		// then
		assertNotNull(accessToken.getValueAsString());
		assertEquals(token, accessToken.getValueAsString());
		assertEquals("nitin", accessToken.getUsername());
		assertEquals("[default-roles-test, offline_access, uma_authorization, ADMIN]", authorities.toString());
	}
}

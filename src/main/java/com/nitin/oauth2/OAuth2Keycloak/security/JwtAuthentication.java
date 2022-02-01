package com.nitin.oauth2.OAuth2Keycloak.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import lombok.ToString;

@ToString
public class JwtAuthentication extends AbstractAuthenticationToken{

	private final AccessToken accessToken;
	
	
	public JwtAuthentication(AccessToken accessToken) {
		super(accessToken.getAuthorities());
		this.accessToken=accessToken;
	}
	
	
	@Override
	public Object getCredentials() {
		return accessToken.getValueAsString() ;
	}

	@Override
	public Object getPrincipal() {
		return accessToken.getUsername();
	}

}

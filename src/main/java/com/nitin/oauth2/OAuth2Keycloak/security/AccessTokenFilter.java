package com.nitin.oauth2.OAuth2Keycloak.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import com.nitin.oauth2.OAuth2Keycloak.exception.InvalidTokenException;
import com.nitin.oauth2.OAuth2Keycloak.validator.JwtTokenValidator;

//@Slf4j
public class AccessTokenFilter extends AbstractAuthenticationProcessingFilter{
	
	
	private final JwtTokenValidator tokenValidator;
	private Logger log = LoggerFactory.getLogger(AccessTokenFilter.class);

	public AccessTokenFilter(JwtTokenValidator tokenValidator, AuthenticationManager authenticationManager,
			AuthenticationFailureHandler authenticationFailureHandler) {
		super(AnyRequestMatcher.INSTANCE);
		setAuthenticationManager(authenticationManager);
		setAuthenticationFailureHandler(authenticationFailureHandler);
		this.tokenValidator = tokenValidator;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		log.debug(" Attempting to authenticate for a request {}", request.getRequestURI());

		String authorizationHeader = extractAuthorizationHeaderAsString(request);
		log.debug(" authorizationHeader= "+authorizationHeader );
		AccessToken accessToken = tokenValidator.validateAuthorizationHeader(authorizationHeader);
		log.debug("accessToken ="+accessToken);
		return this.getAuthenticationManager().authenticate(new JwtAuthentication(accessToken));
	}


	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
	
		log.debug("Successfully authentication for the request {} ",request.getRequestURI());
		
		SecurityContextHolder.getContext().setAuthentication(authResult);
		chain.doFilter(request, response);
	}
	
	
	private String extractAuthorizationHeaderAsString(HttpServletRequest request) {
		try {
			return request.getHeader("Authorization");
		} catch (Exception e) {
			throw new InvalidTokenException("There is not Authorization header in a request",e); 
		}
	}
	
	

}

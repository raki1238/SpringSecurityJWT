package com.auth.security.springsecurejwt.security;

import com.auth.security.springsecurejwt.model.AuthenticationToken;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.ObjectUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter{

    private static final String TOKEN_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "qwerty ";

    public TokenAuthenticationFilter() {
        super("/secured/**");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest,
                                                HttpServletResponse httpServletResponse)
            throws AuthenticationException, IOException, ServletException {
        AuthenticationToken token = validateHeader(httpServletRequest.getHeader(TOKEN_HEADER));
        if(ObjectUtils.isEmpty(token)){
            throw new ServletException("401 - UNAUTHORIZED");
        }
        return getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                         FilterChain filterChain, Authentication authResult)
        throws  IOException, ServletException{
        super.successfulAuthentication(request, response, filterChain, authResult);
        filterChain.doFilter(request, response);
    }

    private AuthenticationToken validateHeader(String authenticationHeader){
        if(StringUtils.isBlank(authenticationHeader) || !authenticationHeader.startsWith(TOKEN_HEADER)){
            return null;
        }
        return new AuthenticationToken(authenticationHeader.replace(TOKEN_PREFIX, ""));
    }

}

package com.auth.security.springsecurejwt.security;

import com.auth.security.springsecurejwt.model.AuthenticationToken;
import com.auth.security.springsecurejwt.model.LoginUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class TokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static final String SECURITY_KEY = "1@34$7juiasd(8";

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken)
            throws AuthenticationException {

    }

    @Override
    protected UserDetails retrieveUser(String s, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken)
            throws AuthenticationException {
        AuthenticationToken authenticationToken = (AuthenticationToken) usernamePasswordAuthenticationToken;
        String token = authenticationToken.getToken();
        Claims claim = Jwts.parser().setSigningKey(SECURITY_KEY).parseClaimsJws(token).getBody();
        return new LoginUserDetails(claim.getSubject(),
                token,
                Long.parseLong((String) claim.get("Id")),
                AuthorityUtils.commaSeparatedStringToAuthorityList((String) claim.get("role")));
    }
}

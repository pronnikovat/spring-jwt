package com.example.springjwt.security;

import com.example.springjwt.model.AuthenticationToken;
import com.example.springjwt.model.JwtUserDetails;
import com.example.springjwt.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    private final JwtValidator jwtValidator;

    @Autowired
    public JwtAuthenticationProvider(JwtValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
        AuthenticationToken authenticationToken = (AuthenticationToken) usernamePasswordAuthenticationToken;
        String token = authenticationToken.getToken();
        User user = jwtValidator.validate(token);
        System.out.println(user);
        if (user == null) {
            throw new RuntimeException("JWT is incorrect");
        }
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList(user.getRole());
        return new JwtUserDetails(user.getUsername(), user.getId(), token, grantedAuthorities);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return AuthenticationToken.class.isAssignableFrom(aClass);
    }
}

package com.example.springjwt.security;

import com.example.springjwt.model.User;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;

@Component
public class JwtValidator {
    public User validate(String token) {
        User user = null;
        try {
            Claims body = Jwts.parser()
                    .setSigningKey("secret")
                    .parseClaimsJws(token)
                    .getBody();
            user = new User();
            user.setUsername(body.getSubject());
            user.setId(Long.parseLong((String) body.get("userId")));
            user.setRole((String) body.get("password"));
            user.setRole((String) body.get("role"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return user;
    }
}

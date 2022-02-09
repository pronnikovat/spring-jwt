package com.example.springjwt.controller;

import com.example.springjwt.model.User;
import com.example.springjwt.security.JwtGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/login")
public class LoginController {
    private final JwtGenerator jwtGenerator;

    @Autowired
    public LoginController(JwtGenerator jwtGenerator) {
        this.jwtGenerator = jwtGenerator;
    }

    @PostMapping
    public ResponseEntity login(@RequestBody final User user) {
        if (user.getUsername().equals("admin") && user.getPassword().equals("1234")) {
            user.setRole("ROLE_ADMIN");
            user.setId(1l);
            return ResponseEntity.ok().header("JWT", jwtGenerator.generate(user)).body(null);
        } else if (user.getUsername().equals("user") && user.getPassword().equals("1234")) {
            user.setRole("ROLE_USER");
            user.setId(2l);
            return ResponseEntity.ok().header("JWT", jwtGenerator.generate(user)).body(null);
        } else {
            return ResponseEntity.badRequest().body(null);
        }
    }
}

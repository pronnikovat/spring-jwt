package com.example.springjwt.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MainController {

    @GetMapping
    @PostAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public String test() {
        return "User Test Service OK!";
    }


    @RequestMapping(value = "/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String roleTest() {
        return "Admin Test Service OK!";
    }
}

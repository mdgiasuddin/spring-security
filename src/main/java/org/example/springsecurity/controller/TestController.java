package org.example.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @PreAuthorize("hasAnyRole('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin() {
        return "Hello Admin! Welcome.";
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("/user")
    public String greetUser() {
        return "Hello User! Welcome.";
    }
}

package org.example.springsecurity.service.impl;

import lombok.RequiredArgsConstructor;
import org.example.springsecurity.config.security.JwtService;
import org.example.springsecurity.model.dto.request.LoginRequest;
import org.example.springsecurity.model.dto.response.LoginResponse;
import org.example.springsecurity.model.entity.User;
import org.example.springsecurity.service.JwtAuthService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtAuthServiceImpl implements JwtAuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Override
    public LoginResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(), request.password()
                )
        );

        User user = (User) authentication.getPrincipal();

        return new LoginResponse(jwtService.generateAccessToken(user));
    }
}

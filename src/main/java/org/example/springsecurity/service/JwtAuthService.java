package org.example.springsecurity.service;

import org.example.springsecurity.model.dto.request.LoginRequest;
import org.example.springsecurity.model.dto.response.LoginResponse;

public interface JwtAuthService {
    LoginResponse login(LoginRequest request);
}

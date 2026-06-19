package com.innowise.authservice.controller;

import com.innowise.authservice.dto.request.*;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.JwtResponse;
import com.innowise.authservice.dto.response.ValidateTokenResponse;
import com.innowise.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest) {
        return new ResponseEntity<>(authService.register(registerRequest), HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody LoginRequest loginRequest) {
        return new ResponseEntity<>(authService.login(loginRequest), HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> refresh(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidateTokenResponse> validate(
            @RequestBody ValidateTokenRequest validateTokenRequest
    ) {
        return ResponseEntity.ok(authService.validateToken(validateTokenRequest));
    }

    @PostMapping("/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AuthResponse> updateRole(
            @RequestBody UpdateRoleRequest updateRoleRequest
    ) {
        return new ResponseEntity<>(authService.updateRole(updateRoleRequest), HttpStatus.OK);
    }
}

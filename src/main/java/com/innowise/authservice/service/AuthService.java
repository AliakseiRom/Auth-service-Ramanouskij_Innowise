package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.JwtResponse;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final CredentialRepository credentialRepository;

    private final CredentialMapper credentialMapper;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    public AuthResponse register(RegisterRequest registerRequest) {

        Credential credential = credentialMapper.toCredential(registerRequest);
        credential.setPassword(
                passwordEncoder.encode(registerRequest.getPassword())
        );

        credentialRepository.save(credential);

        return new AuthResponse("User registered successfully");
    }

    public JwtResponse login(LoginRequest loginRequest) {

        Optional<Credential> credentialOptional = credentialRepository.findByLogin(loginRequest.getLogin());
        if (credentialOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        Credential credential = credentialOptional.get();

        if (!passwordEncoder.matches(loginRequest.getPassword(), credential.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        String accessToken = jwtService.generateAccessToken(credential);

        String refreshToken = jwtService.generateRefreshToken(credential);

        return new JwtResponse(accessToken, refreshToken);
    }

    public JwtResponse refresh(RefreshRequest refreshRequest) {

        if (!jwtService.isTokenValid(refreshRequest.getRefreshToken())) {
            throw new RuntimeException("Invalid refresh token");
        }

        String login = jwtService.extractLogin(refreshRequest.getRefreshToken());

        Credential credential = credentialRepository.findByLogin(login)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(credential);
        String newRefreshToken = jwtService.generateRefreshToken(credential);

        return new JwtResponse(newAccessToken, newRefreshToken);
    }
}

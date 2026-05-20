package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.repository.CredentialRepository;
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

    public AuthResponse register(RegisterRequest registerRequest) {

        Credential credential = credentialMapper.toCredential(registerRequest);
        credential.setPassword(
                passwordEncoder.encode(registerRequest.getPassword())
        );

        credentialRepository.save(credential);

        return new AuthResponse("User registered successfully");
    }

    public AuthResponse login(LoginRequest loginRequest) {

        Optional<Credential> credentialOptional = credentialRepository.findByLogin(loginRequest.getLogin());
        if (credentialOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        Credential credential = credentialOptional.get();

        if (!passwordEncoder.matches(loginRequest.getPassword(), credential.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        return new AuthResponse("User logged in successfully");
    }
}

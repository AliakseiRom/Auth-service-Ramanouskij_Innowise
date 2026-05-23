package com.innowise.authservice.service;

import com.innowise.authservice.client.UserClient;
import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.dto.request.*;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.JwtResponse;
import com.innowise.authservice.dto.response.ValidateTokenResponse;
import com.innowise.authservice.exception.AccessDeniedException;
import com.innowise.authservice.exception.EntityNotExistException;
import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.exception.JwtException;
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

    private final UserClient userClient;

    public AuthResponse register(RegisterRequest registerRequest) {

        CreateUserRequest userRequest = new CreateUserRequest();

        userRequest.setName(registerRequest.getName());
        userRequest.setSurname(registerRequest.getSurname());
        userRequest.setBirthDate(registerRequest.getBirthDate());
        userRequest.setEmail(registerRequest.getEmail());

        Long userId = userClient.createUser(userRequest);

        Credential credential = credentialMapper.toCredential(registerRequest);

        credential.setUserId(userId);

        credential.setPassword(
                passwordEncoder.encode(registerRequest.getPassword())
        );

        if (credentialRepository.existsCredentialByLogin(registerRequest.getLogin())) {
            throw new InvalidCredentialsException("Login already in use");
        }

        credentialRepository.save(credential);

        return new AuthResponse("User registered successfully");
    }

    public JwtResponse login(LoginRequest loginRequest) {

        Optional<Credential> credentialOptional =
                credentialRepository.findByLogin(loginRequest.getLogin());
        if (credentialOptional.isEmpty() || !passwordEncoder.matches(
                loginRequest.getPassword(),
                credentialOptional.get().getPassword())
        ) {
            throw new AccessDeniedException("Access denied");
        }

        Credential credential = credentialOptional.get();

        String accessToken = jwtService.generateAccessToken(credential);

        String refreshToken = jwtService.generateRefreshToken(credential);

        return new JwtResponse(accessToken, refreshToken);
    }

    public JwtResponse refresh(RefreshRequest refreshRequest) {

        String refreshToken = refreshRequest.getRefreshToken();

        if (!jwtService.isRefreshTokenValid(refreshToken)) {
            throw new InvalidCredentialsException("Invalid refresh token");
        }

        String login = jwtService.extractLogin(refreshRequest.getRefreshToken());

        Credential credential = credentialRepository.findByLogin(login)
                .orElseThrow(() -> new EntityNotExistException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(credential);
        String newRefreshToken = jwtService.generateRefreshToken(credential);

        return new JwtResponse(newAccessToken, newRefreshToken);
    }

    public ValidateTokenResponse validateToken(ValidateTokenRequest validateTokenRequest) {

        String accessToken = validateTokenRequest.getAccessToken();

        if (!jwtService.isAccessTokenValid(accessToken)) {
            throw new JwtException("Invalid access token");
        }

        String login = jwtService.extractLogin(accessToken);
        Long userId = jwtService.extractUserId(accessToken);
        String role = jwtService.extractRole(accessToken);

        return new ValidateTokenResponse(true, login, userId, role);
    }

    public AuthResponse updateRole(UpdateRoleRequest updateRoleRequest) {
        Credential credential = credentialRepository.findByLogin(updateRoleRequest.getLogin())
                .orElseThrow(() -> new EntityNotExistException("User not found"));

        credential.setRole(updateRoleRequest.getRole());

        credentialRepository.save(credential);

        return new AuthResponse("User's role updated successfully");
    }
}

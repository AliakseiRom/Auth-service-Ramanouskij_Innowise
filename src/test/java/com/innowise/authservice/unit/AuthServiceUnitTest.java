package com.innowise.authservice.unit;

import com.innowise.authservice.client.UserClient;
import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.JwtResponse;
import com.innowise.authservice.exception.AccessDeniedException;
import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.security.jwt.JwtService;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.util.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private CredentialMapper credentialMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private UserClient userClient;

    @InjectMocks
    private AuthService authService;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private Credential credential;

    @BeforeEach
    void setUp() {

        registerRequest = new RegisterRequest();
        registerRequest.setLogin("testLogin");
        registerRequest.setPassword("12345");
        registerRequest.setEmail("test@gmail.com");

        loginRequest = new LoginRequest();
        loginRequest.setLogin("testLogin");
        loginRequest.setPassword("12345");

        credential = new Credential();
        credential.setId(1L);
        credential.setLogin("testLogin");
        credential.setPassword("encodedPassword");
        credential.setRole(Role.USER);
        credential.setUserId(10L);
    }

    @Test
    void register_ShouldRegisterUserSuccessfully() {

        when(credentialMapper.toCredential(registerRequest))
                .thenReturn(credential);

        when(passwordEncoder.encode(registerRequest.getPassword()))
                .thenReturn("encodedPassword");

        when(credentialRepository.save(any(Credential.class)))
                .thenReturn(credential);

        AuthResponse response = authService.register(registerRequest);

        assertEquals(
                "User registered successfully",
                response.getMessage()
        );

        verify(credentialRepository, times(1))
                .save(any(Credential.class));
    }

    @Test
    void login_ShouldReturnTokensSuccessfully() {

        when(credentialRepository.findByLogin(loginRequest.getLogin()))
                .thenReturn(Optional.of(credential));

        when(passwordEncoder.matches(
                loginRequest.getPassword(),
                credential.getPassword()
        )).thenReturn(true);

        when(jwtService.generateAccessToken(credential))
                .thenReturn("accessToken");

        when(jwtService.generateRefreshToken(credential))
                .thenReturn("refreshToken");

        JwtResponse response = authService.login(loginRequest);

        assertEquals("accessToken", response.getAccessToken());
        assertEquals("refreshToken", response.getRefreshToken());
    }

    @Test
    void login_ShouldThrowException_WhenUserNotFound() {

        when(credentialRepository.findByLogin(loginRequest.getLogin()))
                .thenReturn(Optional.empty());

        assertThrows(
                AccessDeniedException.class,
                () -> authService.login(loginRequest)
        );
    }

    @Test
    void login_ShouldThrowException_WhenPasswordInvalid() {

        when(credentialRepository.findByLogin(loginRequest.getLogin()))
                .thenReturn(Optional.of(credential));

        when(passwordEncoder.matches(
                loginRequest.getPassword(),
                credential.getPassword()
        )).thenReturn(false);

        assertThrows(
                AccessDeniedException.class,
                () -> authService.login(loginRequest)
        );
    }

    @Test
    void refresh_ShouldReturnNewTokensSuccessfully() {

        RefreshRequest request =
                new RefreshRequest("validRefreshToken");

        when(jwtService.isRefreshTokenValid("validRefreshToken"))
                .thenReturn(true);

        when(jwtService.extractLogin("validRefreshToken"))
                .thenReturn("testLogin");

        when(credentialRepository.findByLogin("testLogin"))
                .thenReturn(Optional.of(credential));

        when(jwtService.generateAccessToken(credential))
                .thenReturn("newAccessToken");

        when(jwtService.generateRefreshToken(credential))
                .thenReturn("newRefreshToken");

        JwtResponse response = authService.refresh(request);

        assertEquals(
                "newAccessToken",
                response.getAccessToken()
        );

        assertEquals(
                "newRefreshToken",
                response.getRefreshToken()
        );
    }

    @Test
    void refresh_ShouldThrowException_WhenTokenInvalid() {

        RefreshRequest request =
                new RefreshRequest("invalidToken");

        when(jwtService.isRefreshTokenValid("invalidToken"))
                .thenReturn(false);

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.refresh(request)
        );
    }
}
package com.innowise.authservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.client.UserClient;
import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.util.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private UserClient userClient;

    @BeforeEach
    void setUp() {
        credentialRepository.deleteAll();
    }

    @Test
    void register_ShouldReturn200() throws Exception {

        RegisterRequest request = new RegisterRequest();
        request.setLogin("alex");
        request.setPassword("12345");
        request.setName("Alex");
        request.setSurname("Smith");
        request.setEmail("alex@test.com");

        when(userClient.createUser(
                ArgumentMatchers.any(CreateUserRequest.class)
        )).thenReturn(1L);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("User registered successfully"));
    }

    @Test
    void login_ShouldReturnTokens() throws Exception {

        Credential credential = new Credential();
        credential.setLogin("alex");
        credential.setPassword(passwordEncoder.encode("12345"));
        credential.setUserId(1L);
        credential.setRole(Role.USER);

        credentialRepository.save(credential);

        LoginRequest request = new LoginRequest();
        request.setLogin("alex");
        request.setPassword("12345");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void login_ShouldReturn403_WhenUserNotFound() throws Exception {

        LoginRequest request = new LoginRequest();
        request.setLogin("unknown");
        request.setPassword("12345");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void login_ShouldReturn403_WhenPasswordInvalid() throws Exception {

        Credential credential = new Credential();
        credential.setLogin("alex");
        credential.setPassword(passwordEncoder.encode("correct"));
        credential.setUserId(1L);
        credential.setRole(Role.USER);

        credentialRepository.save(credential);

        LoginRequest request = new LoginRequest();
        request.setLogin("alex");
        request.setPassword("wrong");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void refresh_ShouldReturnNewTokens() throws Exception {

        Credential credential = new Credential();
        credential.setLogin("alex");
        credential.setPassword(passwordEncoder.encode("12345"));
        credential.setUserId(1L);
        credential.setRole(Role.USER);

        credentialRepository.save(credential);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setLogin("alex");
        loginRequest.setPassword("12345");

        String loginResponse = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andReturn()
                .getResponse()
                .getContentAsString();

        String refreshToken = objectMapper
                .readTree(loginResponse)
                .get("refreshToken")
                .asText();

        RefreshRequest refreshRequest = new RefreshRequest(refreshToken);

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void refresh_ShouldReturn400_WhenTokenInvalid() throws Exception {

        RefreshRequest request =
                new RefreshRequest("invalid-token");

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}

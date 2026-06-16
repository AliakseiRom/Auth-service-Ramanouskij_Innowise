package com.innowise.authservice.client;

import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.client.dto.CreateUserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserClient {

    private final RestClient restClient;

    @Value("${spring.services.user-service.url}")
    private String userServiceUrl;

    public Long createUser(CreateUserRequest request) {
        String url = userServiceUrl + "/user/internal";

        CreateUserResponse response = restClient.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(CreateUserResponse.class);

        return response.getId();
    }

    public void rollbackUserCreation(String email) {
        String url = userServiceUrl + "/user/internal?email={email}";

        restClient.delete()
                .uri(url, email)
                .retrieve()
                .toBodilessEntity();
    }
}
package com.innowise.authservice.client;

import com.innowise.authservice.client.dto.CreateUserRequest;
import com.innowise.authservice.client.dto.CreateUserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
@RequiredArgsConstructor
public class UserClient {

    private final RestClient restClient;

    @Value("${spring.services.user-service.url}")
    private String userServiceUrl;

    public Long createUser(CreateUserRequest request) {

        CreateUserResponse response = restClient.post()
                .uri(userServiceUrl + "/user/internal")
                .body(request)
                .retrieve()
                .body(CreateUserResponse.class);

        return response.getId();
    }
}

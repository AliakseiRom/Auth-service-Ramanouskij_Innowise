package com.innowise.authservice.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ValidateTokenResponse {

    private boolean valid;
    private String login;
    private Long userId;
    private String role;
}

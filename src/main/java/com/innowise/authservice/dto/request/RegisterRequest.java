package com.innowise.authservice.dto.request;

import lombok.Data;

@Data
public class RegisterRequest {

    private Long userId;

    private String login;

    private String password;
}

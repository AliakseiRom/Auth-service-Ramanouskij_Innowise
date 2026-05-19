package com.innowise.authservice.dto.response;

import lombok.Data;

@Data
public class AuthResponse {

    private String message;

    public AuthResponse(String message) {
        this.message = message;
    }
}

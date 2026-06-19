package com.innowise.authservice.dto.request;

import lombok.Data;

@Data
public class ValidateTokenRequest {

    String accessToken;
}

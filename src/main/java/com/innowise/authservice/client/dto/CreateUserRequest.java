package com.innowise.authservice.client.dto;

import lombok.Data;

import java.time.LocalDate;

@Data
public class CreateUserRequest {

    private String name;

    private String surname;

    private LocalDate birthDate;

    private String email;
}
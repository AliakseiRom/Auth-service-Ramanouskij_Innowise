package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.model.Credential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CredentialMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "role", expression = "java(com.innowise.authservice.util.Role.USER)")
    @Mapping(target = "password", ignore = true)
    Credential toCredential(RegisterRequest registerRequest);
}

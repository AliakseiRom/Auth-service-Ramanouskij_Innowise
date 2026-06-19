package com.innowise.authservice.dto.request;

import com.innowise.authservice.util.Role;
import lombok.Data;

@Data
public class UpdateRoleRequest {

    private String login;

    private Role role;
}

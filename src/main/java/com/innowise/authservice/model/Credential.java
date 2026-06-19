package com.innowise.authservice.model;

import com.innowise.authservice.util.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "credentials")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Credential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", unique=true, nullable=false)
    private Long userId;

    @Column(nullable = false)
    private String login;

    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;
}

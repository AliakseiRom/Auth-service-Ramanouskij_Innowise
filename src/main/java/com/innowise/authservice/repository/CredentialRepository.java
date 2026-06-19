package com.innowise.authservice.repository;

import com.innowise.authservice.model.Credential;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {
    Optional<Credential> findByLogin(String login);

    boolean existsCredentialByLogin(String login);

    Credential getByLogin(String login);

    List<Credential> findByLogin(String login, Limit limit);
}

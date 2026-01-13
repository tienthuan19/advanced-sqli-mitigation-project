package com.cybersecurity.application.repository;

import com.cybersecurity.application.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByUsernameAndPassword(String username, String password);
}
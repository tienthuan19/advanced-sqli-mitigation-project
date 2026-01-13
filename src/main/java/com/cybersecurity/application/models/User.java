package com.cybersecurity.application.models;

import jakarta.persistence.*;
import lombok.Data;
import java.util.UUID; // Nhớ import cái này

@Entity
@Table(name = "users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;
}
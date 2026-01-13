package com.cybersecurity.application.models;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "ip_blacklist")
@Data
public class IpBlacklist {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String ipAddress;

    private String fingerprint;
    private LocalDateTime blockedAt;
    private LocalDateTime unblockAt;
}
package com.cybersecurity.application.models;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_logs")
@Data
public class SecurityLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ipAddress;
    private String fingerprint;
    private String endpoint;

    @Column(columnDefinition = "TEXT")
    private String payload; // Nội dung câu lệnh tấn công

    private String violationType; // "SQL_INJECTION", "XSS"
    private LocalDateTime timestamp;

    @PrePersist
    public void prePersist() {
        this.timestamp = LocalDateTime.now();
    }
}
package com.cybersecurity.application.repository;

import com.cybersecurity.application.models.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {
}

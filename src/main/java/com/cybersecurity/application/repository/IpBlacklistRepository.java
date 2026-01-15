package com.cybersecurity.application.repository;

import com.cybersecurity.application.models.IpBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface IpBlacklistRepository extends JpaRepository<IpBlacklist, Long> {
    IpBlacklist findByIpAddress(String ip);
    List<IpBlacklist> findByFingerprintAndUnblockAtAfter(String fingerprint, LocalDateTime now);
}

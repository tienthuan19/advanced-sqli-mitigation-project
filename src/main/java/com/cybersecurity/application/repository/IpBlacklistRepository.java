package com.cybersecurity.application.repository;

import com.cybersecurity.application.models.IpBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IpBlacklistRepository extends JpaRepository<IpBlacklist, Long> {
    IpBlacklist findByIpAddress(String ip);
}

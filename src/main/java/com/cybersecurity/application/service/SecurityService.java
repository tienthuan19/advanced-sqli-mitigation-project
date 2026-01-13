package com.cybersecurity.application.service;

import com.cybersecurity.application.models.IpBlacklist;
import com.cybersecurity.application.models.SecurityLog;
import com.cybersecurity.application.repository.IpBlacklistRepository;
import com.cybersecurity.application.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@RequiredArgsConstructor
@Service
public class SecurityService {

    @Autowired
    private final SecurityLogRepository logRepo;

    private final IpBlacklistRepository blacklistRepo;

    private static final Logger logger = LoggerFactory.getLogger(SecurityService.class);

    private final ConcurrentHashMap<String, Integer> violationCounts = new ConcurrentHashMap<>();

    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|update\\s+.*\\s+set|drop\\s+table|--|;|'\\s+or\\s+'|'\\s+and\\s+')",
            Pattern.CASE_INSENSITIVE
    );

    public boolean isMalicious(String content) {
        if (content == null) return false;
        return SQLI_PATTERN.matcher(content).find();
    }

    public void logViolation(String ip, String fingerprint, String payload, String endpoint) {
        SecurityLog log = new SecurityLog();
        log.setIpAddress(ip);
        log.setFingerprint(fingerprint);
        log.setPayload(payload);
        log.setEndpoint(endpoint);
        log.setViolationType("SQL_INJECTION");
        logRepo.save(log);

        int count = violationCounts.getOrDefault(fingerprint, 0) + 1;
        violationCounts.put(fingerprint, count);

        if (count >= 3) {
            blockIpFirewall(ip, fingerprint);
            violationCounts.remove(fingerprint);
        }
    }

    private void blockIpFirewall(String ip, String fingerprint) {
        if (blacklistRepo.findByIpAddress(ip) != null) return;
        try {
            ProcessBuilder pb = new ProcessBuilder("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP");
            pb.start();
            System.out.println("FIREWALL BLOCKED IP: " + ip);

            IpBlacklist blacklist = new IpBlacklist();
            blacklist.setIpAddress(ip);
            blacklist.setFingerprint(fingerprint);
            blacklist.setBlockedAt(LocalDateTime.now());
            blacklist.setUnblockAt(LocalDateTime.now().plusHours(24));
            blacklistRepo.save(blacklist);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Scheduled(fixedRate = 60000)
    public void unblockExpiredIps() {
        System.out.println("⏳ Scanning for expired IP bans...");

        List<IpBlacklist> expiredList = blacklistRepo.findAll();

        LocalDateTime now = LocalDateTime.now();

        for (IpBlacklist record : expiredList) {
            if (record.getUnblockAt().isBefore(now)) {
                unblockIpFirewall(record);
            }
        }
    }

    private void unblockIpFirewall(IpBlacklist record) {
        try {
            String ip = record.getIpAddress();

            ProcessBuilder pb = new ProcessBuilder("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP");
            pb.start();

            blacklistRepo.delete(record);

            System.out.println("✅ UNBLOCKED IP: " + ip);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

package com.cybersecurity.application.service;

import com.cybersecurity.application.models.IpBlacklist;
import com.cybersecurity.application.models.SecurityLog;
import com.cybersecurity.application.repository.IpBlacklistRepository;
import com.cybersecurity.application.repository.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
public class SecurityService {

    @Autowired
    private SecurityLogRepository logRepo;

    @Autowired
    private IpBlacklistRepository blacklistRepo;

    // Map lưu tạm số lần vi phạm trong RAM (Fingerprint -> Count)
    private final ConcurrentHashMap<String, Integer> violationCounts = new ConcurrentHashMap<>();

    // Regex phát hiện SQL Injection (Cơ bản & Nâng cao)
    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|update\\s+.*\\s+set|drop\\s+table|--|;|'\\s+or\\s+'|'\\s+and\\s+')",
            Pattern.CASE_INSENSITIVE
    );

    public boolean isMalicious(String content) {
        if (content == null) return false;
        return SQLI_PATTERN.matcher(content).find();
    }

    public void logViolation(String ip, String fingerprint, String payload, String endpoint) {
        // 1. Lưu log vào DB
        SecurityLog log = new SecurityLog();
        log.setIpAddress(ip);
        log.setFingerprint(fingerprint);
        log.setPayload(payload);
        log.setEndpoint(endpoint);
        log.setViolationType("SQL_INJECTION");
        logRepo.save(log);

        // 2. Xử lý logic 3 Strikes
        int count = violationCounts.getOrDefault(fingerprint, 0) + 1;
        violationCounts.put(fingerprint, count);

        if (count >= 3) {
            blockIpFirewall(ip, fingerprint);
            violationCounts.remove(fingerprint); // Reset sau khi block
        }
    }

    private void blockIpFirewall(String ip, String fingerprint) {
        // Kiểm tra xem đã chặn chưa
        if (blacklistRepo.findByIpAddress(ip) == null) return;

        try {
            // A. Gọi lệnh System (Linux Iptables)
            // Lệnh: sudo iptables -A INPUT -s <IP> -j DROP
            ProcessBuilder pb = new ProcessBuilder("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP");
            pb.start();
            System.out.println("FIREWALL BLOCKED IP: " + ip);

            // B. Lưu vào DB để quản lý thời gian mở khóa (24h)
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

    // Scheduled Task: Tự động quét DB để mở khóa sau 24h (Bạn cần thêm @EnableScheduling ở Main)
    public void unblockExpiredIps() {
        // Logic: Tìm các IP hết hạn -> Chạy lệnh "sudo iptables -D INPUT -s <IP> -j DROP" -> Xóa khỏi DB
    }
}
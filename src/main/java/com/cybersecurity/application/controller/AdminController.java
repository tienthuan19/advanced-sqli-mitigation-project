package com.cybersecurity.application.controller;

import com.cybersecurity.application.models.IpBlacklist;
import com.cybersecurity.application.models.SecurityLog;
import com.cybersecurity.application.repository.IpBlacklistRepository;
import com.cybersecurity.application.repository.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "http://localhost:3000") // Quan trọng cho Frontend
public class AdminController {
    @Autowired
    private SecurityLogRepository logRepo;

    @Autowired
    private IpBlacklistRepository blacklistRepo;

    // Xem lịch sử tấn công
    @GetMapping("/logs")
    public List<SecurityLog> getLogs() {
        // Nên sắp xếp mới nhất lên đầu (giảm dần theo ID)
        return logRepo.findAll();
    }

    // Xem danh sách đang bị chặn (Firewall Status)
    @GetMapping("/blacklist")
    public List<IpBlacklist> getBlacklist() {
        return blacklistRepo.findAll();
    }
}

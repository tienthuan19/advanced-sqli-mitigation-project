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
@CrossOrigin(origins = "*")
public class AdminController {
    @Autowired
    private SecurityLogRepository logRepo;

    @Autowired
    private IpBlacklistRepository blacklistRepo;

    @GetMapping("/logs")
    public List<SecurityLog> getLogs() {
        return logRepo.findAll();
    }

    @GetMapping("/blacklist")
    public List<IpBlacklist> getBlacklist() {
        return blacklistRepo.findAll();
    }
}

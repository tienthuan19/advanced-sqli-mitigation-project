package com.cybersecurity.application.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/vulnerable")
@CrossOrigin(origins = "http://localhost:3000")
public class VulnerableController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 1. Classic SQLi
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");

        String sql = "SELECT count(*) FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

        System.out.println("Executing SQL: " + sql);

        try {
            int count = jdbcTemplate.queryForObject(sql, Integer.class);
            if (count > 0) {
                return "Login Success! Welcome " + username;
            } else {
                return "Invalid credentials";
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 2. Union-Based SQLi
    @GetMapping("/products")
    public List<Map<String, Object>> searchProducts(@RequestParam String query) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";
        System.out.println("Executing SQL: " + sql);

        return jdbcTemplate.queryForList(sql);
    }

    // 3. Error-Based (Detail)
    @GetMapping("/product/{id}")
    public List<Map<String, Object>> getProductDetail(@PathVariable String id) {
        String sql = "SELECT * FROM products WHERE id = " + id;
        System.out.println("Executing SQL: " + sql);

        return jdbcTemplate.queryForList(sql);
    }
}
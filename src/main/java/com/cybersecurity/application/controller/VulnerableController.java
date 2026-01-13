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

    // 1. Lỗ hổng Classic SQLi (Login Bypass)
    // Kịch bản: Kẻ tấn công đăng nhập mà không cần password đúng.
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");

        // LỖ HỔNG: Cộng chuỗi trực tiếp
        String sql = "SELECT count(*) FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

        System.out.println("Executing SQL: " + sql); // Log ra để xem query bị biến đổi thế nào

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

    // 2. Lỗ hổng Union-Based SQLi (Search)
    // Kịch bản: Kẻ tấn công dùng UNION để lấy dữ liệu từ bảng `users` khi đang search `products`.
    @GetMapping("/products")
    public List<Map<String, Object>> searchProducts(@RequestParam String query) {
        // LỖ HỔNG: Cộng chuỗi vào câu lệnh LIKE
        String sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";

        System.out.println("Executing SQL: " + sql);

        // Trả về danh sách sản phẩm (hoặc dữ liệu user bị leak)
        return jdbcTemplate.queryForList(sql);
    }

    // 3. Lỗ hổng Error-Based / Blind SQLi (Detail)
    // Kịch bản: Nhập ID sai định dạng để lộ cấu trúc DB hoặc query
    @GetMapping("/product/{id}")
    public List<Map<String, Object>> getProductDetail(@PathVariable String id) {
        // LỖ HỔNG: Cộng chuỗi ID (thường ID là số, nhưng hacker truyền chuỗi tấn công)
        String sql = "SELECT * FROM products WHERE id = " + id;

        System.out.println("Executing SQL: " + sql);

        return jdbcTemplate.queryForList(sql);
    }
}
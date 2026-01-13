package com.cybersecurity.application.controller;

import com.cybersecurity.application.models.Product;
import com.cybersecurity.application.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @Autowired
    private ProductRepository productRepo;

    @GetMapping("/products")
    public List<Product> search(@RequestParam String query) {
        // An toàn tuyệt đối nhờ JPA
        return productRepo.findByNameContaining(query);
    }
}

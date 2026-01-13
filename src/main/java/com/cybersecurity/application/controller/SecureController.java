package com.cybersecurity.application.controller;

import com.cybersecurity.application.models.Product;
import com.cybersecurity.application.models.User;
import com.cybersecurity.application.repository.ProductRepository;
import com.cybersecurity.application.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/secure")
@CrossOrigin(origins = "http://localhost:3000")
public class SecureController {

    @Autowired
    private ProductRepository productRepo;

    @Autowired
    private UserRepository userRepo;

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");

        Optional<User> user = userRepo.findByUsernameAndPassword(username, password);
        System.out.println(user.isPresent());
        if (user.isPresent()) {
            return "Login Success! Welcome " + user.get().getUsername();
        } else {
            return "Invalid credentials";
        }
    }

    @GetMapping("/products")
    public List<Product> searchProducts(@RequestParam String query) {
        return productRepo.findByNameContaining(query);
    }

    @GetMapping("/product/{id}")
    public ResponseEntity<?> getProductDetail(@PathVariable String id) {
        try {
            Long productId = Long.parseLong(id);

            Optional<Product> product = productRepo.findById(productId);

            if (product.isPresent()) {
                return ResponseEntity.ok(List.of(product.get()));
            } else {
                return ResponseEntity.ok(List.of());
            }
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body("Invalid ID format");
        }
    }
}
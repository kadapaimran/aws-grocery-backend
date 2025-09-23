package com.klu.ecommerce.controller;

import com.klu.ecommerce.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*")
public class AuthController {
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    // Signup
    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> registerUser(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        try {
            String username = request.get("username");
            String email = request.get("email");
            String password = request.get("password");

            String message = userService.registerUser(username, email, password);
            response.put("message", message);
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            response.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            response.put("message", "Signup failed due to server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    // Login
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        try {
            String username = request.get("username");
            String password = request.get("password");

            String token = userService.loginUser(username, password);
            response.put("token", token);
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            response.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            response.put("message", "Login failed due to server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}

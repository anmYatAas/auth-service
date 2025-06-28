package com.auth.service.controller;

import com.auth.service.model.request.LoginRequest;
import com.auth.service.model.request.SignupRequest;
import com.auth.service.service.CognitoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final CognitoService cognitoService;

    public AuthController(CognitoService cognitoService) {
        this.cognitoService = cognitoService;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest request) {
        cognitoService.signUpUser(request.getUsername(), request.getPassword(), request.getEmail());
        return ResponseEntity.ok("User signed up. Please confirm via email if required.");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request) {
        Map<String, String> tokens = cognitoService.loginUser(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(tokens);
    }
}


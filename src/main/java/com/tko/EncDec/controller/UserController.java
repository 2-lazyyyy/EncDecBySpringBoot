package com.tko.EncDec.controller;

import com.tko.EncDec.dto.UserDTO;
import com.tko.EncDec.model.Users;
import com.tko.EncDec.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }


    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Users user) {
        try {
            userService.registerUser(user);
            Map<String, String> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("success", "true");
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", e.getMessage());
            errorResponse.put("success", "false");
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody Users user) {
        String jwtToken = userService.verify(user);
        if ("Failure".equals(jwtToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Invalid credentials"));
        }

        // Return the token in the response body
        Map<String, String> response = new HashMap<>();
        response.put("token", jwtToken);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        try {
            List<UserDTO> users = userService.getAllUsers();
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            // Log the exception if needed
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }



    @PostMapping("/update")
    public Users updateUser(@RequestBody Users user){
        return userService.updateUser(user);
    }
}

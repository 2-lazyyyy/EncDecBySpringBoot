package com.tko.EncDec.service;

import com.tko.EncDec.dto.FileRecordDTO;
import com.tko.EncDec.dto.UserDTO;
import com.tko.EncDec.model.FileRecord;
import com.tko.EncDec.model.Users;
import com.tko.EncDec.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public Users registerUser(Users user){
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new IllegalArgumentException("User with username " + user.getUsername() + " already exists.");
        }
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user);

    }

    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(user -> {
                    List<FileRecordDTO> fileRecordDTOs = user.getFileRecords().stream()
                            .map(file -> new FileRecordDTO(
                                    file.getId(),
                                    file.getOriginalFilePath(),
                                    file.getEncryptedFilePath(),
                                    file.getDecryptedFilePath(),
                                    file.getUserKey(), // Include userKey
                                    file.getKeyLength() // Include keyLength
                            ))
                            .collect(Collectors.toList());

                    return new UserDTO(user.getId(), user.getUsername(), fileRecordDTOs);
                })
                .collect(Collectors.toList());
    }


    public Users updateUser(Users user) {
        user.setPassword(encoder.encode(user.getPassword()));
        user.setId(user.getId());
        user.setUsername(user.getUsername());
        return userRepository.save(user);
    }

    public String verify(Users user) {
        // Validate user input: Ensure username and password are not empty
        if (user.getUsername() == null || user.getUsername().trim().isEmpty() ||
                user.getPassword() == null || user.getPassword().trim().isEmpty()) {
            System.out.println("Empty username or password provided.");
            return "Failure";
        }

        try {
            // Attempt to authenticate the user with valid credentials
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername().trim(), user.getPassword().trim()));

            // If authentication is successful, generate and return the JWT token
            if (authentication.isAuthenticated()) {
                System.out.println("User authenticated: " + user.getUsername());
                return jwtService.generateToken(user.getUsername());
            } else {
                System.out.println("Authentication failed for: " + user.getUsername());
                return "Failure";
            }
        } catch (AuthenticationException ex) {
            // If authentication fails, catch the exception and return a failure message
            System.out.println("Authentication failed: " + ex.getMessage());
            return "Failure";
        }
    }




}

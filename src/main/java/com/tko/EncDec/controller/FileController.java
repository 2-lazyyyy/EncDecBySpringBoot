package com.tko.EncDec.controller;

import com.tko.EncDec.dto.*;
import com.tko.EncDec.model.UserPrincipal;
import com.tko.EncDec.service.FileService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/files")
public class FileController {

    @Autowired
    private final FileService fileService;

    @Value("${file.storage.location}")
    private String storageLocation;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            // Get the authenticated user's username
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            // Call the service to upload the file and associate it with the user
            fileService.uploadFile(file, userPrincipal.getUsername());
            return ResponseEntity.ok("{\"message\":\"File uploaded successfully\"}");
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File upload failed");
        }
    }


    @PostMapping("/encrypt")
    public ResponseEntity<String> encryptFile(@RequestBody FileEncryptionRequest request, HttpServletRequest httpRequest) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            fileService.encryptFile(request, userPrincipal.getUsername());
            return ResponseEntity.ok("File encrypted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File encryption failed: " + e.getMessage());
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decryptFile(@RequestBody FileDecryptionRequest request,
                                             HttpServletRequest httpRequest) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            fileService.decryptFile(request, userPrincipal.getUsername());
            return ResponseEntity.ok("File decrypted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File decryption failed: " + e.getMessage());
        }
    }

    @PostMapping("/decryptwc")
    public ResponseEntity<String> decryptFileWithoutCheck(@RequestBody FileDecryptionRequest request,
                                              HttpServletRequest httpRequest) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            fileService.decryptFileWithoutCheck(request, userPrincipal.getUsername());
            return ResponseEntity.ok("File decrypted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File decryption failed: " + e.getMessage());
        }
    }

    @GetMapping("/list")
    public ResponseEntity<List<FileRecordSummaryDTO>> getFiles(
            @RequestParam("filetype") String filetype,
            @RequestParam(value = "keyword", required = false) String keyword,
            @RequestParam(value = "sortOrder", defaultValue = "asc") String sortOrder,
            @RequestParam(value = "sortField", defaultValue = "filename") String sortField) {
        try {
            // Get the authenticated user's username
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            // Validate filetype input
            if (!isValidFileType(filetype)) {
                return ResponseEntity.badRequest().body(null);  // Invalid filetype response
            }

            // Retrieve files based on the filetype, keyword, sortOrder, and sortField
            List<FileRecordSummaryDTO> files = fileService.getFiles(userPrincipal.getUsername(), filetype, keyword, sortOrder, sortField);

            return ResponseEntity.ok(files);
        } catch (Exception e) {
            // Log the exception for debugging
            e.printStackTrace();  // Replace with logging in production
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    // Helper method to validate filetype (add more types if needed)
    private boolean isValidFileType(String filetype) {
        return filetype.equals("ori") || filetype.equals("enc") || filetype.equals("dec");
    }



    @GetMapping("/get")
    public ResponseEntity<Resource> getFileForUser(
            @RequestParam("filename") String filename,
            @RequestParam("filetype") String fileType) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String authenticatedUsername = ((UserPrincipal) authentication.getPrincipal()).getUsername();
            Resource resource = fileService.getFileForUser(filename, fileType, authenticatedUsername);
            if (resource == null || !resource.exists()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
            String contentType = determineContentType(fileType);
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(contentType))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .body(resource);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private String determineContentType(String fileType) {
        switch (fileType.toLowerCase()) {
            case "pdf":
                return "application/pdf";
            case "docx":
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
            case "txt":
                return "text/plain";
            default:
                return "application/octet-stream";
        }
    }


    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteFile(@RequestBody DeleteFileRequestDTO request) {
        try {
            // Get the authenticated user's username
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String authenticatedUsername = ((UserPrincipal) authentication.getPrincipal()).getUsername();

            // Delegate the deletion to the service
            fileService.deleteFile(request, authenticatedUsername);

            return ResponseEntity.ok().build();
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            // Log the error for further investigation
            Logger logger = LoggerFactory.getLogger(getClass());
            logger.error("An error occurred during file deletion", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/seekey")
    public ResponseEntity<String> seeKey(@RequestBody FileKeyDTO request) {
        try {
            // Get the authenticated user's username
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String authenticatedUsername = ((UserPrincipal) authentication.getPrincipal()).getUsername();

            // Delegate the deletion to the service
            String key = fileService.seeKey(request, authenticatedUsername);

            return ResponseEntity.ok(key);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            // Log the error for further investigation
            Logger logger = LoggerFactory.getLogger(getClass());
            logger.error("An error occurred during finding key", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PutMapping("/rename")
    public ResponseEntity<String> renameFile(
            @RequestParam("fileId") Long fileId,
            @RequestParam("newFilename") String newFilename,
            @RequestParam("fileType") String fileType) {
        try {
            // Get the authenticated user's username from the SecurityContext
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String authenticatedUsername = authentication.getName();

            // Call the service to rename the file
            boolean isRenamed = fileService.renameFile(fileId, newFilename, fileType, authenticatedUsername);

            if (isRenamed) {
                return ResponseEntity.ok("File renamed successfully");
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("You are not authorized to rename this file.");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error renaming file");
        }
    }



}

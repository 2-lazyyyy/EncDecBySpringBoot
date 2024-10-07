package com.tko.EncDec.service;

import com.tko.EncDec.dto.*;
import com.tko.EncDec.model.FileRecord;
import com.tko.EncDec.model.Users;
import com.tko.EncDec.repository.FileRecordRepository;
import com.tko.EncDec.repository.UserRepository;
import com.tko.EncDec.util.QuickSortUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class FileService {

    private final FileRecordRepository fileRecordRepository;
    private final UserRepository userRepository;
    private final String storageLocation;

    @Autowired
    private AuthenticationManager authenticationManager;

    

    public FileService(FileRecordRepository fileRecordRepository,
                        UserRepository userRepository) {
        this.fileRecordRepository = fileRecordRepository;
        this.userRepository = userRepository;

        // Dynamically resolve the absolute path to the file storage directory
        this.storageLocation = Paths.get(System.getProperty("user.dir"), "./fileStorage").normalize().toString();
    }


    public void uploadFile(MultipartFile file, String username) throws IOException {
        try {
            // Retrieve the user
            Users user = userRepository.findByUsername(username);

            if (user == null) {
                throw new IllegalArgumentException("User with username " + username + " does not exist.");
            }

            // Build the file path using the storage location and the file's original name
            String originalFilePath = Paths.get(storageLocation, file.getOriginalFilename()).toString();

            // Log the file path
            System.out.println("Storing file at: " + originalFilePath);

            // Ensure the directory exists
            File targetFile = new File(originalFilePath);
            if (!targetFile.getParentFile().exists()) {
                boolean dirsCreated = targetFile.getParentFile().mkdirs(); // Create the directory if it doesn't exist
                System.out.println("Directories created: " + dirsCreated);  // Log if the directory was created
            }

            // Check if file path exists
            if (Files.exists(targetFile.toPath())) {
                System.out.println("File already exists. Overwriting: " + originalFilePath);
            } else {
                System.out.println("File does not exist. Creating a new file.");
            }

            // Transfer the file to the target location
            file.transferTo(targetFile);

            // Log confirmation that file transfer was successful
            System.out.println("File successfully stored at: " + originalFilePath);

            // Create and save the file record
            FileRecord fileRecord = new FileRecord();
            fileRecord.setOriginalFilePath(originalFilePath);
            fileRecord.setUserKey(""); // Placeholder, update this as per your logic
            fileRecord.setUser(user);
            fileRecord.setOriginalFileCreatedTime(LocalDateTime.now());

            fileRecordRepository.save(fileRecord);
        } catch (IOException e) {
            System.err.println("Failed to store file: " + e.getMessage());
            throw new IOException("Could not store file. Please try again!", e);
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            throw new RuntimeException("An internal error occurred. Please try again later.", e);
        }
    }


//    public List<FileRecordSummaryDTO> getFiles(String username, String filetype, String keyword, String sortOrder, String sortField) {
//        Users user = userRepository.findByUsername(username);
//
//        // Fetch files based on the filetype
//        List<FileRecord> fileRecords = fileRecordRepository.findByUserAndFiletype(user, filetype);
//
//        // Filter or Search files based on the keyword
//        List<FileRecord> filteredFiles = fileRecords.stream()
//                .filter(file -> {
//                    String fileName = getFileName(file, filetype).toLowerCase();
//                    return keyword == null || keyword.isEmpty() || fileName.contains(keyword.toLowerCase());
//                })
//                .collect(Collectors.toList());
//
//        // Define the comparator based on sortField and sortOrder
//        Comparator<FileRecord> comparator = (f1, f2) -> {
//            if ("filename".equalsIgnoreCase(sortField)) {
//                // Sort by filename
//                String name1 = getFileName(f1, filetype).toLowerCase();
//                String name2 = getFileName(f2, filetype).toLowerCase();
//                return sortOrder.equalsIgnoreCase("asc") ? name1.compareTo(name2) : name2.compareTo(name1);
//            } else if ("createdTime".equalsIgnoreCase(sortField)) {
//                // Sort by createdTime based on filetype
//                LocalDateTime time1 = getCreatedTimeByFiletype(f1, filetype);
//                LocalDateTime time2 = getCreatedTimeByFiletype(f2, filetype);
//                return sortOrder.equalsIgnoreCase("asc") ? time1.compareTo(time2) : time2.compareTo(time1);
//            } else {
//                // Default sorting by filename if no valid sortField is provided
//                String name1 = getFileName(f1, filetype).toLowerCase();
//                String name2 = getFileName(f2, filetype).toLowerCase();
//                return sortOrder.equalsIgnoreCase("asc") ? name1.compareTo(name2) : name2.compareTo(name1);
//            }
//        };
//
//        // Apply QuickSort
//        QuickSortUtil.quickSort(filteredFiles, comparator);
//
//        // Map to DTOs or Return the result
//        return filteredFiles.stream()
//                .map(file -> new FileRecordSummaryDTO(
//                        file.getId(),
//                        file.getOriginalFilePath(),
//                        file.getEncryptedFilePath(),
//                        file.getDecryptedFilePath(),
//                        file.getOriginalFileCreatedTime(),  // Specific creation time for the original file path
//                        file.getEncryptedFileCreatedTime(), // Specific creation time for the encrypted file path
//                        file.getDecryptedFileCreatedTime()  // Specific creation time for the decrypted file path
//                ))
//                .collect(Collectors.toList());
//    }

    // Method to manually check if 'keyword' is a substring of 'fileName'
    private boolean isSubstring(String fileName, String keyword) {
        int fileNameLength = fileName.length();
        int keywordLength = keyword.length();

        // If keyword is longer than fileName, it can't be a substring
        if (keywordLength > fileNameLength) {
            return false;
        }

        // Check each possible starting position in fileName
        for (int i = 0; i <= fileNameLength - keywordLength; i++) {
            int j;
            // Check if keyword matches starting from position i
            for (j = 0; j < keywordLength; j++) {
                if (fileName.charAt(i + j) != keyword.charAt(j)) {
                    break;
                }
            }
            // If full keyword matched, return true
            if (j == keywordLength) {
                return true;
            }
        }
        return false;
    }

    public List<FileRecordSummaryDTO> getFiles(String username, String filetype, String keyword, String sortOrder, String sortField) {
        Users user = userRepository.findByUsername(username);

        // Fetch files based on the filetype
        List<FileRecord> fileRecords = fileRecordRepository.findByUserAndFiletype(user, filetype);

        // Filter or Search files based on the keyword
        List<FileRecord> filteredFiles = new ArrayList<>();
        for (FileRecord file : fileRecords) {
            String fileName = getFileName(file, filetype).toLowerCase();
            if (keyword == null || keyword.isEmpty() || isSubstring(fileName, keyword.toLowerCase())) {
                filteredFiles.add(file);
            }
        }

        // Define the comparator based on sortField and sortOrder
        Comparator<FileRecord> comparator = (f1, f2) -> {
            if ("filename".equalsIgnoreCase(sortField)) {
                // Sort by filename
                String name1 = getFileName(f1, filetype).toLowerCase();
                String name2 = getFileName(f2, filetype).toLowerCase();
                return sortOrder.equalsIgnoreCase("asc") ? name1.compareTo(name2) : name2.compareTo(name1);
            } else if ("createdTime".equalsIgnoreCase(sortField)) {
                // Sort by createdTime based on filetype
                LocalDateTime time1 = getCreatedTimeByFiletype(f1, filetype);
                LocalDateTime time2 = getCreatedTimeByFiletype(f2, filetype);
                return sortOrder.equalsIgnoreCase("asc") ? time1.compareTo(time2) : time2.compareTo(time1);
            } else {
                // Default sorting by filename if no valid sortField is provided
                String name1 = getFileName(f1, filetype).toLowerCase();
                String name2 = getFileName(f2, filetype).toLowerCase();
                return sortOrder.equalsIgnoreCase("asc") ? name1.compareTo(name2) : name2.compareTo(name1);
            }
        };

        // Apply QuickSort
        QuickSortUtil.quickSort(filteredFiles, comparator);

        // Map to DTOs or Return the result
        return filteredFiles.stream()
                .map(file -> new FileRecordSummaryDTO(
                        file.getId(),
                        file.getOriginalFilePath(),
                        file.getEncryptedFilePath(),
                        file.getDecryptedFilePath(),
                        file.getOriginalFileCreatedTime(),  // Specific creation time for the original file path
                        file.getEncryptedFileCreatedTime(), // Specific creation time for the encrypted file path
                        file.getDecryptedFileCreatedTime()  // Specific creation time for the decrypted file path
                ))
                .collect(Collectors.toList());
    }



    // Helper method to extract the filename based on the filetype
    private String getFileName(FileRecord file, String filetype) {
        switch (filetype) {
            case "ori":
                return Paths.get(file.getOriginalFilePath()).getFileName().toString();
            case "enc":
                return file.getEncryptedFilePath() != null ? Paths.get(file.getEncryptedFilePath()).getFileName().toString() : "";
            case "dec":
                return file.getDecryptedFilePath() != null ? Paths.get(file.getDecryptedFilePath()).getFileName().toString() : "";
            default:
                return "";
        }
    }

    // Helper method to get the correct created time based on the filetype
    private LocalDateTime getCreatedTimeByFiletype(FileRecord file, String filetype) {
        switch (filetype) {
            case "ori":
                return file.getOriginalFileCreatedTime();
            case "enc":
                return file.getEncryptedFileCreatedTime();
            case "dec":
                return file.getDecryptedFileCreatedTime();
            default:
                return file.getCreatedTime();  // Default to general created time if no specific filetype
        }
    }






    public void encryptFile(FileEncryptionRequest request, String authenticatedUsername) throws Exception {
        // Find the file record by ID
        FileRecord fileRecord = fileRecordRepository.findById(request.getFileId())
                .orElseThrow(() -> new IOException("File record not found"));

        // Check if the file belongs to the authenticated user
        if (!fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
            throw new SecurityException("No file found for the authenticated user");
        }

        // Check if the file is already encrypted
//        if (fileRecord.getEncryptedFilePath() != null) {
//            throw new IllegalArgumentException("This file is already encrypted");
//        }

        // Determine the file paths
        String originalFilePath = fileRecord.getOriginalFilePath();
        String encryptedFilePath = originalFilePath + ".enc";

        // Encrypt the file using the user-defined key
        processFile(Cipher.ENCRYPT_MODE, originalFilePath, encryptedFilePath, request.getUserKey());

        // Update the file record with encryption details
        fileRecord.setUserKey(request.getUserKey());
        fileRecord.setKeyLength(request.getUserKey().length());
        fileRecord.setEncryptedFilePath(encryptedFilePath);
        fileRecord.setEncryptedFileCreatedTime(LocalDateTime.now());

        // Save the updated file record
        fileRecordRepository.save(fileRecord);
    }


    public void decryptFile(FileDecryptionRequest request, String authenticatedUsername) throws Exception {
        // Find the file record by ID
        FileRecord fileRecord = fileRecordRepository.findById(request.getFileId())
                .orElseThrow(() -> new IOException("File record not found"));

        // Check if the file belongs to the authenticated user
        if (!fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
            throw new SecurityException("No file found for the authenticated user");
        }

        // Check if the file is not encrypted
        if (fileRecord.getEncryptedFilePath() == null) {
            throw new IllegalArgumentException("This file is not encrypted");
        }

        // Validate the provided key
        if (request.getUserKey() == null || request.getUserKey().isEmpty()) {
            throw new IllegalArgumentException("User key is null or empty");
        }

        if (fileRecord.getKeyLength() != null && request.getUserKey().length() != fileRecord.getKeyLength()) {
            throw new IllegalArgumentException("User key length does not match the expected length");
        }

        // Determine the file paths
        String encryptedFilePath = fileRecord.getEncryptedFilePath();
        String decryptedFilePath = encryptedFilePath.replace(".enc", ".dec");

        // Decrypt the file using the user-defined key
        processFile(Cipher.DECRYPT_MODE, encryptedFilePath, decryptedFilePath, request.getUserKey());

        // Update the file record with decryption details
        fileRecord.setDecryptedFilePath(decryptedFilePath);
        fileRecord.setDecryptedFileCreatedTime(LocalDateTime.now());
        // Save the updated file record
        fileRecordRepository.save(fileRecord);
    }

    public void decryptFileWithoutCheck(FileDecryptionRequest request, String authenticatedUsername) throws Exception {
        // Find the file record by ID
        FileRecord fileRecord = fileRecordRepository.findById(request.getFileId())
                .orElseThrow(() -> new IOException("File record not found"));

        // Check if the file belongs to the authenticated user
        if (!fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
            throw new SecurityException("No file found for the authenticated user");
        }



        // Validate the provided key
        if (request.getUserKey() == null || request.getUserKey().isEmpty()) {
            throw new IllegalArgumentException("User key is null or empty");
        }



        // Determine the file paths
        String encryptedFilePath = fileRecord.getOriginalFilePath();
        String decryptedFilePath = encryptedFilePath.replace(".enc", ".dec");

        // Decrypt the file using the user-defined key
        processFile(Cipher.DECRYPT_MODE, encryptedFilePath, decryptedFilePath, request.getUserKey());

        // Update the file record with decryption details
        fileRecord.setDecryptedFilePath(decryptedFilePath);
        fileRecord.setDecryptedFileCreatedTime(LocalDateTime.now());
        // Save the updated file record
        fileRecordRepository.save(fileRecord);
    }





    private void processFile(int cipherMode, String inputFile, String outputFile, String userKey) throws Exception {
        byte[] keyBytes = getPaddedKey(userKey);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(cipherMode, key);

        byte[] inputBytes;
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            inputBytes = fis.readAllBytes();
        }

        byte[] outputBytes = cipher.doFinal(inputBytes);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(outputBytes);
        }
    }

    private byte[] getPaddedKey(String userKey) {
        byte[] keyBytes = userKey.getBytes();
        byte[] paddedKey = new byte[16];
        Arrays.fill(paddedKey, (byte) 0);

        // Copy the user key to the start of the padded key
        System.arraycopy(keyBytes, 0, paddedKey, 0, Math.min(keyBytes.length, paddedKey.length));

        return paddedKey;
    }

    public Resource getFileForUser(String filename, String fileType, String authenticatedUsername) throws IOException {
        // Find all file records
        List<FileRecord> fileRecords = fileRecordRepository.findAll();

        // Find the file record with the matching filename in the specified type
        FileRecord fileRecord = searchFileRecords(fileRecords, filename, fileType);

        // Check if the file exists and if the user is authorized to access it
        if (fileRecord == null || !fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
            return null; // User is not authorized or file does not exist
        }

        String filePath = getFilePath(fileRecord, fileType);

        if (filePath == null || filePath.isEmpty()) {
            return null; // File path does not exist
        }

        return loadFileAsResource(filePath);
    }

    private FileRecord searchFileRecords(List<FileRecord> fileRecords, String filename, String fileType) {
        for (FileRecord record : fileRecords) {
            if (matchesFilePath(record, filename, fileType)) {
                return record;
            }
        }
        return null;
    }

    private boolean matchesFilePath(FileRecord record, String filename, String fileType) {
        switch (fileType.toLowerCase()) {
            case "ori":
                return getFileName(record.getOriginalFilePath()).equals(filename);
            case "enc":
                return getFileName(record.getEncryptedFilePath()).equals(filename);
            case "dec":
                return getFileName(record.getDecryptedFilePath()).equals(filename);
            default:
                return false;
        }
    }

    private String getFilePath(FileRecord record, String fileType) {
        switch (fileType.toLowerCase()) {
            case "ori":
                return record.getOriginalFilePath();
            case "enc":
                return record.getEncryptedFilePath();
            case "dec":
                return record.getDecryptedFilePath();
            default:
                return null;
        }
    }

    private String getFileName(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return "";
        }
        Path path = Paths.get(filePath);
        return path.getFileName().toString();
    }

    public Resource loadFileAsResource(String filePath) throws MalformedURLException {
        if (filePath == null || filePath.isEmpty()) {
            return null; // Handle null or empty file path
        }
        Path path = Paths.get(storageLocation).resolve(filePath).normalize();
        return new UrlResource(path.toUri());
    }



    public void deleteFile(DeleteFileRequestDTO request, String authenticatedUsername) throws IOException {
        FileRecord fileRecord = fileRecordRepository.findById(request.getFileId())
                .orElseThrow(() -> new IOException("File record not found"));

        // Validate if the authenticated user is the owner of the file
        if (!fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
            throw new SecurityException("No file found for the authenticated user");
        }

        // Fetch the user to validate the password
        Users user = userRepository.findByUsername(authenticatedUsername);
        if (user == null) {
            throw new SecurityException("User not found");
        }

        // Authenticate using the raw password provided in the request
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticatedUsername, request.getPassword()));

            if (!authentication.isAuthenticated()) {
                throw new SecurityException("Invalid password");
            }
        } catch (BadCredentialsException e) {
            throw new SecurityException("Invalid password", e);
        }

        // Determine which file path to delete based on the file type
        switch (request.getFileType()) {
            case "ori":
                fileRecord.setOriginalFilePath(null);
                break;
            case "enc":
                fileRecord.setEncryptedFilePath(null);
                break;
            case "dec":
                fileRecord.setDecryptedFilePath(null);
                break;
            default:
                throw new IllegalArgumentException("Invalid file type");
        }

        // Save the updated file record
        fileRecordRepository.save(fileRecord);
    }

    public String seeKey(FileKeyDTO request, String authenticatedUsername) throws IOException {
        FileRecord fileRecord = fileRecordRepository.findById(request.getFileId())
                .orElseThrow(() -> new IOException("File record not found"));

        // Validate if the authenticated user is the owner of the file
        if (!fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
            throw new SecurityException("No file found for the authenticated user");
        }

        // Fetch the user to validate the password
        Users user = userRepository.findByUsername(authenticatedUsername);
        if (user == null) {
            throw new SecurityException("User not found");
        }

        // Authenticate using the raw password provided in the request
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticatedUsername, request.getPassword()));

            if (!authentication.isAuthenticated()) {
                throw new SecurityException("Invalid password");
            }
        } catch (BadCredentialsException e) {
            throw new SecurityException("Invalid password", e);
        }

        String userKey = fileRecord.getUserKey();
        return userKey;

    }

    public boolean renameFile(Long fileId, String newFilename, String fileType, String authenticatedUsername) throws IOException {
        Optional<FileRecord> optionalFileRecord = fileRecordRepository.findById(fileId);

        if (optionalFileRecord.isPresent()) {
            FileRecord fileRecord = optionalFileRecord.get();

            // Check if the file belongs to the authenticated user
            if (!fileRecord.getUser().getUsername().equals(authenticatedUsername)) {
                return false; // The file does not belong to the authenticated user
            }

            // Get the appropriate file path based on the file type
            String currentFilePath = getFilePath(fileRecord, fileType);

            if (currentFilePath != null && !currentFilePath.isEmpty()) {
                // Construct source and target file paths
                Path sourcePath = Paths.get(currentFilePath);
                Path targetPath = sourcePath.resolveSibling(newFilename);

                // Rename the file in the filesystem
                Files.move(sourcePath, targetPath);

                // Update the file path in the database
                switch (fileType.toLowerCase()) {
                    case "ori":
                        fileRecord.setOriginalFilePath(targetPath.toString());
                        break;
                    case "enc":
                        fileRecord.setEncryptedFilePath(targetPath.toString());
                        break;
                    case "dec":
                        fileRecord.setDecryptedFilePath(targetPath.toString());
                        break;
                    default:
                        return false; // Invalid file type
                }

                // Save the updated record
                fileRecordRepository.save(fileRecord);
                return true;
            } else {
                // File path not found or empty
                return false;
            }
        } else {
            // File record not found
            return false;
        }
    }

}

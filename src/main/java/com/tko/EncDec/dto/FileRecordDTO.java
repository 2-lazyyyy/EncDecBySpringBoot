package com.tko.EncDec.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class FileRecordDTO {

    private Long id;
    private String originalFilePath;
    private String encryptedFilePath;
    private String decryptedFilePath;


    private String userKey; // Sensitive data for internal use only


    private Integer keyLength; // Sensitive data for internal use only

    // Constructor including all fields
    public FileRecordDTO(Long id, String originalFilePath, String encryptedFilePath, String decryptedFilePath, String userKey, Integer keyLength) {
        this.id = id;
        this.originalFilePath = originalFilePath;
        this.encryptedFilePath = encryptedFilePath;
        this.decryptedFilePath = decryptedFilePath;
        this.userKey = userKey;
        this.keyLength = keyLength;
    }
}

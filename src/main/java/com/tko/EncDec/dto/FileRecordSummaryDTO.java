package com.tko.EncDec.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FileRecordSummaryDTO {

    private Long id;
    private String originalFilePath;
    private String encryptedFilePath;
    private String decryptedFilePath;
    private LocalDateTime originalFileCreatedTime;
    private LocalDateTime encryptedFileCreatedTime;
    private LocalDateTime decryptedFileCreatedTime;
}

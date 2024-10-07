package com.tko.EncDec.dto;

import lombok.Data;

@Data
public class FileDecryptionRequest {
    private Long fileId;
    private String userKey;
}
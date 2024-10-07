package com.tko.EncDec.dto;

import lombok.Data;

@Data
public class FileEncryptionRequest {
    private Long fileId;
    private String userKey;
}
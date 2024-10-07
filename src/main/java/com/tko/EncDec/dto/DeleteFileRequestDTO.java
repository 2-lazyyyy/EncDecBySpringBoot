package com.tko.EncDec.dto;

import lombok.Data;

@Data
public class DeleteFileRequestDTO {
    private Long fileId;
    private String fileType; // "ori", "enc", "dec"
    private String password; // User-provided password
}

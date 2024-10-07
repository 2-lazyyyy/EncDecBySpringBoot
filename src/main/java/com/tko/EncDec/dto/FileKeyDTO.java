package com.tko.EncDec.dto;

import lombok.Data;

@Data
public class FileKeyDTO {
    private Long fileId;
    private String password; // User-provided password
}

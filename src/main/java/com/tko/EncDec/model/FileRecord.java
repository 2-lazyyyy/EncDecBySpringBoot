
package com.tko.EncDec.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
public class FileRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String originalFilePath;
    private String encryptedFilePath;
    private String decryptedFilePath;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "MM-dd-yyyy HH:mm:ss")
    private LocalDateTime originalFileCreatedTime;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "MM-dd-yyyy HH:mm:ss")
    private LocalDateTime encryptedFileCreatedTime;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "MM-dd-yyyy HH:mm:ss")
    private LocalDateTime decryptedFileCreatedTime;

    // Replace FileKey with these fields
    private String userKey;
    private Integer keyLength;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "MM-dd-yyyy HH:mm:ss")
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdTime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonBackReference
    private Users user;

    // Default constructor
    public FileRecord() {}

    // Set the created time before persisting the entity
    @PrePersist
    protected void onCreate() {
        this.createdTime = LocalDateTime.now();
    }

    // Set individual file path created times before updating the entity
    @PreUpdate
    protected void onUpdate() {
        if (this.originalFilePath != null && this.originalFileCreatedTime == null) {
            this.originalFileCreatedTime = LocalDateTime.now();
        }
        if (this.encryptedFilePath != null && this.encryptedFileCreatedTime == null) {
            this.encryptedFileCreatedTime = LocalDateTime.now();
        }
        if (this.decryptedFilePath != null && this.decryptedFileCreatedTime == null) {
            this.decryptedFileCreatedTime = LocalDateTime.now();
        }
    }
}

package com.tko.EncDec.model;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.tko.EncDec.model.FileRecord;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Entity
@Data
@AllArgsConstructor
public class Users {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference  // Manage this reference
    private List<FileRecord> fileRecords = new ArrayList<>();

    public Users() {
    }

    public Users orElseThrow(Object userNotFound) {
        return null;
    }
}



package com.tko.EncDec.repository;

import com.tko.EncDec.model.FileRecord;
import com.tko.EncDec.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface FileRecordRepository extends JpaRepository<FileRecord, Long> {



    // Method to find files by user and filetype
    @Query("SELECT f FROM FileRecord f WHERE f.user = :user AND " +
            "((:filetype = 'ori' AND f.originalFilePath IS NOT NULL) OR " +
            "(:filetype = 'enc' AND f.encryptedFilePath IS NOT NULL) OR " +
            "(:filetype = 'dec' AND f.decryptedFilePath IS NOT NULL))")
    List<FileRecord> findByUserAndFiletype(@Param("user") Users user, @Param("filetype") String filetype);
}

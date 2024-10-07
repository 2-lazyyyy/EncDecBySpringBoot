package com.tko.EncDec.repository;

import com.tko.EncDec.model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<Users, Integer> {
    Users findByUsername(String username);

    boolean existsByUsername(String username);
}

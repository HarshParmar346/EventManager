package com.bezkoder.springjwt.repository;

import com.bezkoder.springjwt.models.Organizer;
import com.bezkoder.springjwt.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OrganizerRepo extends JpaRepository<Organizer,Long> {

    Optional<Organizer> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}

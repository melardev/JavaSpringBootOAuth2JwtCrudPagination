package com.melardev.spring.oauth.repositories;


import com.melardev.spring.oauth.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(String username);

}

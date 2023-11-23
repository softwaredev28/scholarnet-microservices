package net.portofolio.studentmanagement.repositories;

import net.portofolio.studentmanagement.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    User findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}

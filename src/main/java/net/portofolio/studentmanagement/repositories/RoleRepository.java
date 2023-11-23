package net.portofolio.studentmanagement.repositories;


import net.portofolio.studentmanagement.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {
    Role findByName(String roleName);

    boolean existsByName(String name);
}

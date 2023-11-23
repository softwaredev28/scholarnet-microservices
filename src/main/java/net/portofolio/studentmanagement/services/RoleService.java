package net.portofolio.studentmanagement.services;


import net.portofolio.studentmanagement.entities.Role;
import net.portofolio.studentmanagement.models.RoleToUserRequest;

import java.util.List;

public interface RoleService {
    Role saveRole(Role request);
    List<Role> findAllRoles();
    void addRoleToUser(RoleToUserRequest request);
}

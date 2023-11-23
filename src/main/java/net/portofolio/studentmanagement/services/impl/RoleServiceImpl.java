package net.portofolio.studentmanagement.services.impl;


import lombok.RequiredArgsConstructor;
import net.portofolio.studentmanagement.entities.Role;
import net.portofolio.studentmanagement.entities.User;
import net.portofolio.studentmanagement.models.RoleToUserRequest;
import net.portofolio.studentmanagement.repositories.RoleRepository;
import net.portofolio.studentmanagement.repositories.UserRepository;
import net.portofolio.studentmanagement.services.RoleService;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Objects;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public Role saveRole(Role request) {

        if(roleRepository.existsByName(request.getName())) {
            throw new ResponseStatusException(CONFLICT, "Role already exists");
        }

        return roleRepository.save(request);
    }

    @Override
    public List<Role> findAllRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void addRoleToUser(RoleToUserRequest request) {
        User user = userRepository.findByUsername(request.getUsername());
        Role role = roleRepository.findByName(request.getRoleName());
        validateRoleForUser(user, role);
        user.getRoles().add(role);
        userRepository.save(user);
    }

    private static void validateRoleForUser(User user, Role role) {
        if(Objects.isNull(user)) {
            throw new ResponseStatusException(NOT_FOUND, "User not found");
        }
        if(Objects.isNull(role)) {
            throw new ResponseStatusException(NOT_FOUND, "Role not found");
        }
        if(user.getRoles().contains(role)) {
            throw new ResponseStatusException(CONFLICT, "User already has this role");
        }
    }
}

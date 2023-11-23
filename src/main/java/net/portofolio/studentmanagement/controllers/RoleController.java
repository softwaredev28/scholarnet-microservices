package net.portofolio.studentmanagement.controllers;


import lombok.RequiredArgsConstructor;
import net.portofolio.studentmanagement.entities.Role;
import net.portofolio.studentmanagement.models.CommonResponse;
import net.portofolio.studentmanagement.models.RoleToUserRequest;
import net.portofolio.studentmanagement.services.RoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequiredArgsConstructor
@RequestMapping("/roles")
public class RoleController {
    private final RoleService roleService;

//    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER', 'ROLE_SUPERVISOR')")
    @PostMapping
    public ResponseEntity<?> saveRole(@RequestBody Role request) {
        CommonResponse<?> response = CommonResponse.builder()
                .data(roleService.saveRole(request))
                .statusCode(CREATED)
                .build();
        return ResponseEntity.status(CREATED).body(response);
    }

//    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER', 'ROLE_SUPERVISOR')")
    @PostMapping("/add-role-to-user")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserRequest request) {
        roleService.addRoleToUser(request);
        CommonResponse<?> response = CommonResponse.builder()
                .data("Role added to user")
                .statusCode(CREATED)
                .build();
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<?> findAllRoles() {
        List<Role> roles = roleService.findAllRoles();
        CommonResponse<?> response = CommonResponse.builder()
                .data(roles)
                .statusCode(OK)
                .build();
        return  ResponseEntity.ok(response);
    }
}

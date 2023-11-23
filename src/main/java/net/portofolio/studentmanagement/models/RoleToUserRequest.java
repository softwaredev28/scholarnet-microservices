package net.portofolio.studentmanagement.models;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class RoleToUserRequest {
    private String username;
    private String roleName;
}

package net.portofolio.studentmanagement.models;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class UserRequest {
    private String name;
    private String username;
    private String email;
    private String password;
    private String confirmPassword;
}

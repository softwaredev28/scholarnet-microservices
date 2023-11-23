package net.portofolio.studentmanagement.models;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class PasswordRequest {
    private String email;
    private String oldPassword;
    private String newPassword;
}

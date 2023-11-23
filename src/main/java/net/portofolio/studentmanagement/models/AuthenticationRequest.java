package net.portofolio.studentmanagement.models;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class AuthenticationRequest {
    private String username;
    private String password;
}

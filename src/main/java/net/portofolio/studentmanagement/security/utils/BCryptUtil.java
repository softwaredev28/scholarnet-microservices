package net.portofolio.studentmanagement.security.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class BCryptUtil {
    private final PasswordEncoder passwordEncoder;

    public String hashPassword(String password){
        return passwordEncoder.encode(password);
    }

    public boolean checkPassword(String oldPassword, String password) {
        return passwordEncoder.matches(oldPassword, password);
    }
}

package net.portofolio.studentmanagement.security.filters;


import lombok.RequiredArgsConstructor;
import net.portofolio.studentmanagement.entities.User;
import net.portofolio.studentmanagement.services.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserFilter {
    private final UserService userService;

    public boolean checkUser(Authentication authentication, String username) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findUserByUsername(username);
        return userDetails.getUsername().equals(user.getUsername());
    }
}

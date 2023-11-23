package net.portofolio.studentmanagement.services;



import net.portofolio.studentmanagement.entities.User;
import net.portofolio.studentmanagement.entities.VerificationToken;
import net.portofolio.studentmanagement.models.UserRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;

public interface UserService {
    // User saveUser(User request);
    User registerUser(UserRequest request);
    User findUserByUsername(String username);
    List<User> findAllUsers();
    void saveVerificationTokenForUser(User user, String token);
    String validateVerificationToken(String token);
    VerificationToken generateNewToken(String oldToken, HttpServletRequest httpServletRequest);
    User findUserByEmail(String email);
    void createPasswordForResetTokenOfUser(User user, String token);
    String validatePasswordResetToken(String token);
    Optional<User> getUserByPasswordResetToken(String token);
    void changePassword(User user, String newPassword);
    boolean checkIfOldPasswordValid(User user, String oldPassword);
}

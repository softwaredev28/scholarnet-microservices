package net.portofolio.studentmanagement.services.impl;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.portofolio.studentmanagement.entities.PasswordResetToken;
import net.portofolio.studentmanagement.entities.User;
import net.portofolio.studentmanagement.entities.VerificationToken;
import net.portofolio.studentmanagement.models.UserRequest;
import net.portofolio.studentmanagement.repositories.PasswordResetTokenRepository;
import net.portofolio.studentmanagement.repositories.RoleRepository;
import net.portofolio.studentmanagement.repositories.UserRepository;
import net.portofolio.studentmanagement.repositories.VerificationTokenRepository;
import net.portofolio.studentmanagement.security.utils.BCryptUtil;
import net.portofolio.studentmanagement.security.utils.JwtUtil;
import net.portofolio.studentmanagement.services.UserService;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

import static org.springframework.http.HttpStatus.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final BCryptUtil bCryptUtil;
    private final JwtUtil jwtUtil;
    private final RoleRepository roleRepository;

    @Override
    public User registerUser(UserRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(CONFLICT, "Email already exists");
        }

        if(!Objects.equals(request.getPassword(), request.getConfirmPassword())) {
            throw new ResponseStatusException(BAD_REQUEST, "Passwords do not match");
        }
        log.info("registerUser: {}", request);
        User user = User.builder()
                .name(request.getName())
                .username(request.getUsername())
                .email(request.getEmail())
                .password(bCryptUtil.hashPassword(request.getPassword()))
                .enable(false)
                .build();

        if(Objects.isNull(user.getRoles())) {
            user.setRoles(Collections.singletonList(roleRepository.findByName("ROLE_USER")));
        }
        return userRepository.save(user);
    }

    @Override
    public User findUserByUsername(String username) {
        log.info("findUserByUsername : {}", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> findAllUsers() {
        log.info("findAllUsers");
        return userRepository.findAll();
    }

    @Override
    public void saveVerificationTokenForUser(User user, String token) {
        log.info("saveVerificationTokenForUser: {}", user);
        verificationTokenRepository.save(new VerificationToken(user, token));
    }

    @Override
    public String validateVerificationToken(String token) {
        log.info("validateVerificationToken: {}", token);
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token).orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Token Not Found"));

        if (Objects.isNull(verificationToken)) {
            return "Invalid";
        }

        User user = verificationToken.getUser();
        Calendar calendar = Calendar.getInstance();

        if(verificationToken.getExpirationTime().getTime() - calendar.getTime().getTime() <= 0) {
            verificationTokenRepository.delete(verificationToken);
            return "Expired";
        }

        user.setEnable(true);
        verificationTokenRepository.save(verificationToken);

        return "Valid";
    }

    @Override
    public VerificationToken generateNewToken(String oldToken, HttpServletRequest httpServletRequest) {
        log.info("generateNewToken (old token) : {}", oldToken);
        VerificationToken verificationToken = verificationTokenRepository.findByToken(oldToken).orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Token Not Found"));

        verificationToken.setToken(jwtUtil.generateNewRegisterToken(verificationToken.getUser(), httpServletRequest));

        verificationTokenRepository.save(verificationToken);

        log.info("generateNewToken: {}", verificationToken.getToken());
        return verificationToken;
    }

    @Override
    public User findUserByEmail(String email) {
        log.info("findUserByEmail: {}", email);
        return userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "User Not Found"));
    }

    @Override
    public void createPasswordForResetTokenOfUser(User user, String token) {
        log.info("createPasswordForResetTokenOfUser: {}", user);
        passwordResetTokenRepository.save(new PasswordResetToken(user, token));
    }

    @Override
    public String validatePasswordResetToken(String token) {
        log.info("validatePasswordResetToken : {}", token);
        PasswordResetToken passwordResetToken = passwordResetTokenRepository.findByToken(token);

        if(Objects.isNull(passwordResetToken)) {
            return "Invalid";
        }

        Calendar calendar = Calendar.getInstance();

        if(passwordResetToken.getExpirationTime().getTime() - calendar.getTime().getTime() <= 0) {
            passwordResetTokenRepository.delete(passwordResetToken);
            return "Expired";
        }
        return "Valid";
    }

    @Override
    public Optional<User> getUserByPasswordResetToken(String token) {
        log.info("getUserByPasswordResetToken : {}", token);
        return Optional.ofNullable(passwordResetTokenRepository.findByToken(token).getUser());
    }

    @Override
    public void changePassword(User user, String newPassword) {
        log.info("changePassword : {}", newPassword);
        user.setPassword(bCryptUtil.hashPassword(newPassword));
        userRepository.save(user);
    }

    @Override
    public boolean checkIfOldPasswordValid(User user, String oldPassword) {
        log.info("checkIfOldPasswordValid : {}", oldPassword);
        return bCryptUtil.checkPassword(oldPassword, user.getPassword());
    }

}

package net.portofolio.studentmanagement.listeners;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.portofolio.studentmanagement.entities.User;
import net.portofolio.studentmanagement.events.RegistrationCompleteEvent;
import net.portofolio.studentmanagement.security.utils.JwtUtil;
import net.portofolio.studentmanagement.services.UserService;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Slf4j
@Component
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {
    private final UserService userService;
    private final JwtUtil jwtUtil;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        // create the verification token for the user with link
        User user = event.getUser();
        String token = jwtUtil.generateRegisterToken(user);

        userService.saveVerificationTokenForUser(user, token);

        // send mail to user
        String url = event.getApplicationUrl() + "/api/auth/verifyRegistration?token=" + token;

        // verificationEmail()
        log.info("click the link to verify: {}", url);
    }
}

package net.portofolio.studentmanagement.events;


import lombok.Getter;
import lombok.Setter;
import net.portofolio.studentmanagement.entities.User;
import org.springframework.context.ApplicationEvent;

@Getter
@Setter
public class RegistrationCompleteEvent extends ApplicationEvent {
    private String applicationUrl;
    private User user;

    public RegistrationCompleteEvent(User user, String applicationUrl) {
        super(user);
        this.user = user;
        this.applicationUrl = applicationUrl;
    }
}

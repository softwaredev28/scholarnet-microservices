package net.portofolio.studentmanagement.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CommonBeanConfig {
    @Bean
    public ObjectMapper objectMapper() {
        return  new ObjectMapper();
    }

}

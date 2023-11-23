package net.portofolio.studentmanagement;

import lombok.RequiredArgsConstructor;
import net.portofolio.studentmanagement.entities.Role;
import net.portofolio.studentmanagement.repositories.RoleRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@RequiredArgsConstructor
public class StudentManagementServiceApplication {
	private final RoleRepository roleRepository;

	public static void main(String[] args) {
		SpringApplication.run(StudentManagementServiceApplication.class, args);
	}

	@Bean
	public ApplicationRunner run() {
		return args -> {
			if(roleRepository.count() == 0) {
				roleRepository.save(new Role(null, "ROLE_USER"));
				roleRepository.save(new Role(null, "ROLE_ADMIN"));
			}
		};
	}
}

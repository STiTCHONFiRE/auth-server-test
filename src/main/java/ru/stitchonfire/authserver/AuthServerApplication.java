package ru.stitchonfire.authserver;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import ru.stitchonfire.authserver.dto.CreateUserDto;
import ru.stitchonfire.authserver.service.UserDetailsServiceImpl;

import java.util.List;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthServerApplication {

	private final UserDetailsServiceImpl userDetailsService;

	public static void main(String[] args) {
		SpringApplication.run(AuthServerApplication.class, args);
	}

	@EventListener(ApplicationReadyEvent.class)
	public void createUser() {
		userDetailsService.createUserInner(
				CreateUserDto.builder()
						.authorities(List.of("lol"))
						.isEnabled(true)
						.userName("test")
						.password("test")
						.build()
		);
	}
}

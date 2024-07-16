package ru.stitchonfire.authserver;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import ru.stitchonfire.authserver.dto.CreateUserDto;
import ru.stitchonfire.authserver.service.UserDetailsServiceImpl;

import java.util.List;

@SpringBootApplication
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthServerApplication {

    UserDetailsServiceImpl userDetailsService;

    @NonFinal
    @Value("${users.admin.username}")
    private String username;
    @NonFinal
    @Value("${users.admin.password}")
    private String password;

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void createUser() {
        userDetailsService.createUserInner(
                CreateUserDto.builder()
                        .authorities(List.of("admin"))
                        .isEnabled(true)
                        .userName(username)
                        .password(password)
                        .build()
        );

        userDetailsService.createUserInner(
                CreateUserDto.builder()
                        .authorities(List.of("user"))
                        .isEnabled(true)
                        .userName("user")
                        .password(password)
                        .build()
        );
    }
}

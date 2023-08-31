package ru.stitchonfire.authserver.controller;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.stitchonfire.authserver.dto.CheckUsernameDto;
import ru.stitchonfire.authserver.dto.CreateUserDto;
import ru.stitchonfire.authserver.dto.UserDto;
import ru.stitchonfire.authserver.service.UserDetailsServiceImpl;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/users")
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {
    UserDetailsServiceImpl userDetailsService;

    @GetMapping()
    public ResponseEntity<List<UserDto>> getUsers() {
        return userDetailsService.getUsers();
    }

    @GetMapping("{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable String id) {
        return userDetailsService.getUserById(id);
    }

    @PostMapping("create")
    public ResponseEntity<UserDto> createUser(@RequestBody CreateUserDto createUserDto) {
        return userDetailsService.createUser(createUserDto);
    }

    @PostMapping("username/check")
    public ResponseEntity<Boolean> checkUsername(@RequestBody CheckUsernameDto checkUsernameDto) {
        return userDetailsService.checkUsername(checkUsernameDto.username());
    }
}

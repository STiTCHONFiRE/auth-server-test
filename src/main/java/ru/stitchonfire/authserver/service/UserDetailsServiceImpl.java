package ru.stitchonfire.authserver.service;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.stitchonfire.authserver.dto.CreateUserDto;
import ru.stitchonfire.authserver.dto.UserDto;
import ru.stitchonfire.authserver.mapper.UserMapper;
import ru.stitchonfire.authserver.model.User;
import ru.stitchonfire.authserver.repository.UserRepository;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserDetailsServiceImpl implements UserDetailsService {
    UserRepository userRepository;
    PasswordEncoder passwordEncoder;
    UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) {
        return userRepository.findByUserName(username)
                .map(UserDetailsImpl::new)
                .orElseThrow(() -> new UsernameNotFoundException(username + "not found."));
    }

    public void createUserInner(CreateUserDto createUserDto) {
        userRepository.save(userMapper.mapCreateUserDto(createUserDto, passwordEncoder.encode(createUserDto.password())));
    }

    public ResponseEntity<UserDto> createUser(CreateUserDto createUserDto) {
        if (!userRepository.existsUserByUserName(createUserDto.userName())) {
            return ResponseEntity.ok(userMapper.mapUserToUserDto(userRepository.saveAndFlush(userMapper.mapCreateUserDto(createUserDto, passwordEncoder.encode(createUserDto.password())))));
        }

        return ResponseEntity.badRequest().build();
    }

    public ResponseEntity<List<UserDto>> getUsers() {
        return ResponseEntity.ok(userRepository.findAll().stream().map(userMapper::mapUserToUserDto).toList());
    }

    public ResponseEntity<UserDto> getUserById(String id) {
        return userRepository
                .findById(UUID.fromString(id))
                .map(user -> ResponseEntity.ok(userMapper.mapUserToUserDto(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    public ResponseEntity<Boolean> checkUsername(String username) {
        return ResponseEntity.ok(!userRepository.existsUserByUserName(username));
    }
}

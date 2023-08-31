package ru.stitchonfire.authserver.dto;

import lombok.Builder;

import java.util.List;

@Builder
public record CreateUserDto(
        String userName,
        String password,
        List<String> authorities,
        boolean isEnabled
) {
}

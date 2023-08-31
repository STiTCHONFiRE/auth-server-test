package ru.stitchonfire.authserver.dto;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Builder
public record UserDto(
        UUID id,
        String userName,
        Boolean isEnabled,
        List<String> authorities,
        Instant creationTimestamp
) {
}

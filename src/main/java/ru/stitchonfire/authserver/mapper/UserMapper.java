package ru.stitchonfire.authserver.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.stitchonfire.authserver.dto.CreateUserDto;
import ru.stitchonfire.authserver.dto.UserDto;
import ru.stitchonfire.authserver.model.User;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "password", source = "passwordEncoded")
    User mapCreateUserDto(CreateUserDto dto, String passwordEncoded);

    UserDto mapUserToUserDto(User user);
}

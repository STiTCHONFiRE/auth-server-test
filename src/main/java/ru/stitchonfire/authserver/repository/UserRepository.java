package ru.stitchonfire.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.stitchonfire.authserver.model.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByUserName(String userName);

    boolean existsUserByUserName(String userName);
}

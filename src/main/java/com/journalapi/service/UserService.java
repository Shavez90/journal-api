package com.journalapi.service;

import com.journalapi.dto.CreateUserRequest;
import java.time.Instant;
import com.journalapi.dto.UserDTO;
import com.journalapi.exception.DuplicateEmailException;
import com.journalapi.exception.UserNotFoundException;
import com.journalapi.model.User;
import com.journalapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public UserDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return mapToDto(user);
    }

    private UserDTO mapToDto(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
    public UserDTO createUser(CreateUserRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEmailException(
                    "Email already exists: " + request.getEmail()
            );
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(request.getPassword()) // hashing later
                .createdAt(Instant.now())
                .build();

        User savedUser = userRepository.save(user);
        return mapToDto(savedUser);
    }

}

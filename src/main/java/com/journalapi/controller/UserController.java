package com.journalapi.controller;

import com.journalapi.dto.CreateUserRequest;
import com.journalapi.dto.UserDTO;
import com.journalapi.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // ================= CREATE USER =================
    // Public signup (no JWT required)

    @PostMapping
    public UserDTO createUser(@RequestBody @Valid CreateUserRequest request) {
        return userService.createUser(request);
    }

    // ================= GET CURRENT USER (JWT) =================
    // For logged-in USER or ADMIN to fetch own profile

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/me")
    public UserDTO getCurrentUser(Authentication authentication) {
        return userService.getUserByUsername(authentication.getName());
    }

    // ================= ADMIN LOOKUP BY USERNAME =================
    // Admin-only user lookup

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/{username}")
    public UserDTO getUserByUsername(@PathVariable String username) {
        return userService.getUserByUsername(username);
    }
}

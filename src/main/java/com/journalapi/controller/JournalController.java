package com.journalapi.controller;

import com.journalapi.dto.CreateJournalRequest;
import com.journalapi.dto.JournalResponseDTO;
import com.journalapi.dto.UpdateJournalRequest;
import com.journalapi.exception.UserNotFoundException;
import com.journalapi.model.User;
import com.journalapi.repository.UserRepository;
import com.journalapi.service.JournalService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/journals")
@RequiredArgsConstructor
public class JournalController {

    private final JournalService journalService;
    private final UserRepository userRepository;

    /**
     * Extract the authenticated user from Spring Security context
     */
    private User getAuthenticatedUser() {
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        String username = authentication.getName();


        return userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UserNotFoundException("User not found: " + username));
    }

    // ================= CREATE =================

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @PostMapping
    public JournalResponseDTO createJournal(
            @RequestBody @Valid CreateJournalRequest request) {

        User currentUser = getAuthenticatedUser();
        return journalService.createJournal(currentUser.getUsername(), request);

    }

    // ================= UPDATE =================

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @PutMapping("/{journalId}")
    public JournalResponseDTO updateJournal(
            @PathVariable String journalId,
            @RequestBody @Valid UpdateJournalRequest request) {

        User currentUser = getAuthenticatedUser();
        return journalService.updateJournal(
                journalId,
                currentUser.getId(),
                request
        );
    }

    // ================= DELETE =================

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @DeleteMapping("/{journalId}")
    public void deleteJournal(@PathVariable String journalId) {

        User currentUser = getAuthenticatedUser();
        journalService.deleteJournal(journalId, currentUser.getId());
    }

    // ================= READ =================

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping
    public List<JournalResponseDTO> getUserJournals() {

        User currentUser = getAuthenticatedUser();
        return journalService.getJournalsByUserId(currentUser.getId());
    }
}

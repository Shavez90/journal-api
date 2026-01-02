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
     * ✅ ADDED (already by you, now actually USED everywhere)
     *
     * PURPOSE:
     * - Extract the REAL authenticated user from Spring Security
     * - This replaces ALL userId request params
     *
     * FLOW:
     * JWT → SecurityContext → Authentication → username → User (DB)
     */
    private User getAuthenticatedUser() {
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        String username = authentication.getName();

        return userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UserNotFoundException("User not found: " + username));
    }

    /**
     * ❌ REMOVED: @RequestParam String userId
     * ✅ ADDED: authenticated user from SecurityContext
     *
     * WHY:
     * - Client must NOT control identity
     * - Server decides who is creating the journal
     */
    @PostMapping
    public JournalResponseDTO createJournal(
            @RequestBody @Valid CreateJournalRequest request) {

        User currentUser = getAuthenticatedUser();
        return journalService.createJournal(currentUser.getId(), request);
    }

    /**
     * ❌ REMOVED: @RequestParam String userId
     * ✅ ADDED: ownership enforced using authenticated user's ID
     *
     * SECURITY:
     * - Even if client guesses journalId, service blocks access
     * - 403 Forbidden if not owner
     */
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

    /**
     * ❌ REMOVED: @RequestParam String userId
     * ✅ ADDED: server-side identity enforcement
     *
     * RESULT:
     * - Client can delete ONLY their own journals
     */
    @DeleteMapping("/{journalId}")
    public void deleteJournal(@PathVariable String journalId) {

        User currentUser = getAuthenticatedUser();
        journalService.deleteJournal(journalId, currentUser.getId());
    }

    /**
     * ❌ REMOVED: @RequestParam String userId
     * ✅ ADDED: server fetches journals ONLY for authenticated user
     *
     * DATA LEAK PREVENTION:
     * - No way to fetch another user's journals
     */
    @GetMapping
    public List<JournalResponseDTO> getUserJournals() {

        User currentUser = getAuthenticatedUser();
        return journalService.getJournalsByUserId(currentUser.getId());
    }
}

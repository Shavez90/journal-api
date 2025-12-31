package com.journalapi.controller;

import com.journalapi.dto.CreateJournalRequest;
import com.journalapi.dto.JournalResponseDTO;
import com.journalapi.dto.UpdateJournalRequest;
import com.journalapi.service.JournalService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/journals")
@RequiredArgsConstructor
public class JournalController {

    private final JournalService journalService;

    @PostMapping
    public JournalResponseDTO createJournal(
            @RequestParam String userId,
            @RequestBody @Valid CreateJournalRequest request) {

        return journalService.createJournal(userId, request);
    }
    @PutMapping("/{journalId}")
    public JournalResponseDTO updateJournal(
            @PathVariable String journalId,
            @RequestParam String userId,
            @RequestBody @Valid UpdateJournalRequest request) {

        return journalService.updateJournal(journalId, userId, request);
    }

    @DeleteMapping("/{journalId}")
    public void deleteJournal(
            @PathVariable String journalId,
            @RequestParam String userId) {

        journalService.deleteJournal(journalId, userId);
    }


    @GetMapping
    public List<JournalResponseDTO> getUserJournals(
            @RequestParam String userId) {

        return journalService.getJournalsByUserId(userId);
    }
}

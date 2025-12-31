package com.journalapi.controller;

import com.journalapi.dto.CreateJournalRequest;
import com.journalapi.dto.JournalResponseDTO;
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

    @GetMapping
    public List<JournalResponseDTO> getUserJournals(
            @RequestParam String userId) {

        return journalService.getJournalsByUserId(userId);
    }
}

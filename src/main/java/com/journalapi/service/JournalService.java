package com.journalapi.service;

import com.journalapi.dto.CreateJournalRequest;
import com.journalapi.dto.JournalResponseDTO;
import com.journalapi.model.Journal;
import com.journalapi.repository.JournalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JournalService {

    private final JournalRepository journalRepository;

    public JournalResponseDTO createJournal(String userId, CreateJournalRequest request) {

        Journal journal = Journal.builder()
                .userId(userId)
                .title(request.getTitle())
                .content(request.getContent())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        Journal savedJournal = journalRepository.save(journal);
        return mapToDto(savedJournal);
    }

    public List<JournalResponseDTO> getJournalsByUserId(String userId) {
        return journalRepository.findAllByUserId(userId)
                .stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    private JournalResponseDTO mapToDto(Journal journal) {
        return JournalResponseDTO.builder()
                .id(journal.getId())
                .title(journal.getTitle())
                .content(journal.getContent())
                .createdAt(journal.getCreatedAt())
                .updatedAt(journal.getUpdatedAt())
                .build();
    }
}

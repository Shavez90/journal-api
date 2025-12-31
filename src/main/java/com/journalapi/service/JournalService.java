package com.journalapi.service;

import com.journalapi.model.Journal;
import com.journalapi.repository.JournalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JournalService {

    private final JournalRepository journalRepository;

    public Journal createJournal(String userId, String title, String content) {

        Journal journal = Journal.builder()
                .userId(userId)
                .title(title)
                .content(content)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        return journalRepository.save(journal);
    }

    public List<Journal> getJournalsByUserId(String userId) {
        return journalRepository.findAllByUserId(userId);
    }
}

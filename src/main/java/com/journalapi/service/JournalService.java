package com.journalapi.service;

import com.journalapi.dto.CreateJournalRequest;
import com.journalapi.dto.JournalResponseDTO;
import com.journalapi.dto.UpdateJournalRequest;
import com.journalapi.exception.ForbiddenException;
import com.journalapi.exception.JournalNotFoundException;
import com.journalapi.exception.UserNotFoundException;
import com.journalapi.model.Journal;
import com.journalapi.model.User;
import com.journalapi.repository.JournalRepository;
import com.journalapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JournalService {

    private final JournalRepository journalRepository;
    private final UserRepository userRepository;

    // CREATE JOURNAL (ownership from username → userId)
    public JournalResponseDTO createJournal(String username, CreateJournalRequest request) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        Journal journal = Journal.builder()
                .userId(user.getId())               // ✅ ownership stored internally
                .title(request.getTitle())
                .content(request.getContent())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        return mapToDto(journalRepository.save(journal));
    }
    // GET journals for authenticated user only
    public List<JournalResponseDTO> getJournalsByUserId(String userId) {
        return journalRepository.findAllByUserId(userId)
                .stream()
                .map(this::mapToDto)
                .toList();
    }

    // GET MY JOURNALS (JWT user → DB user → journals)
    public List<JournalResponseDTO> getMyJournals(String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return journalRepository.findAllByUserId(user.getId())
                .stream()
                .map(this::mapToDto)
                .toList();
    }

    // UPDATE JOURNAL (ownership enforced)
    public JournalResponseDTO updateJournal(
            String journalId,
            String username,
            UpdateJournalRequest request

    ) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        Journal journal = journalRepository.findById(journalId)
                .orElseThrow(() -> new JournalNotFoundException("Journal not found"));

        if (!journal.getUserId().equals(user.getId())) {
            throw new ForbiddenException("You do not own this journal");
        }

        journal.setTitle(request.getTitle());
        journal.setContent(request.getContent());
        journal.setUpdatedAt(Instant.now());

        return mapToDto(journalRepository.save(journal));
    }

    // DELETE JOURNAL (ownership enforced)
    public void deleteJournal(String journalId, String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        Journal journal = journalRepository.findById(journalId)
                .orElseThrow(() -> new JournalNotFoundException("Journal not found"));

        if (!journal.getUserId().equals(user.getId())) {
            throw new ForbiddenException("You do not own this journal");
        }

        journalRepository.delete(journal);
    }

    // DTO MAPPER
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

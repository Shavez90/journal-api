package com.journalapi.dto;

import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JournalResponseDTO {

    private String id;
    private String title;
    private String content;
    private Instant createdAt;
    private Instant updatedAt;
}

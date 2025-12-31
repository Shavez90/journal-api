package com.journalapi.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Document(collection = "journals")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Journal {

    @Id
    private String id;

    private String userId;

    private String title;

    private String content;

    private Instant createdAt;

    private Instant updatedAt;
}

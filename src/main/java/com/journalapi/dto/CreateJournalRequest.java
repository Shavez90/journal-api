package com.journalapi.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateJournalRequest {

    @NotBlank
    private String title;

    @NotBlank
    private String content;
}

package com.journalapi.repository;

import com.journalapi.model.Journal;
import com.journalapi.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface JournalRepository extends MongoRepository<Journal, String> {

    List<Journal> findAllByUserId(String userId);
}
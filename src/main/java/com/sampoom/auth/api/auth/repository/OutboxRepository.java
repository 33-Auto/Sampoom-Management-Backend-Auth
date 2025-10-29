package com.sampoom.auth.api.auth.repository;

import com.sampoom.auth.api.auth.outbox.OutboxEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface OutboxRepository extends JpaRepository<OutboxEvent, Long> {
    List<OutboxEvent> findTop200ByPublishedFalseOrderByCreatedAtAsc();
}
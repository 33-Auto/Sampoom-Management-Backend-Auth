package com.sampoom.auth.api.auth.outbox;

import com.sampoom.auth.api.auth.repository.OutboxRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OutboxRelay {

    private final OutboxRepository repo;
    private final KafkaTemplate<String, String> kafka;

    @Value("${app.topics.user-events:user-events}")
    private String userEventsTopic;

    @Scheduled(fixedDelayString = "${app.outbox.relay-interval-ms:2000}")
    @Transactional
    public void publishPendingEvents() {
        List<OutboxEvent> batch = repo.findTop200ByPublishedFalseOrderByCreatedAtAsc();
        if (batch.isEmpty()) return;

        for (OutboxEvent e : batch) {
            kafka.send(userEventsTopic, String.valueOf(e.getAggregateId()), e.getPayload());
            e.setPublished(true);
        }
        // JPA @Transactional 이므로 여기서 커밋
        log.info("Outbox published: {} events", batch.size());
    }
}
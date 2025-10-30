package com.sampoom.auth.api.auth.outbox;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * 발행하지 않은 Outbox에 쌓인 이벤트를 주기적으로 일괄 처리
 */

@Slf4j
@Component
@RequiredArgsConstructor
public class OutboxRelay {

    private final OutboxRepository repo;
    private final KafkaTemplate<String, String> kafka;

    // auth-events 토픽
    @Value("${app.topics.auth-events:auth-events}")
    private String authEventsTopic;

    @Scheduled(fixedDelayString = "${app.outbox.relay-interval-ms:10000}")
    @Transactional
    public void publishPendingEvents() {
        log.info("주기적으로 Outbox를 감시중입니다.");
        // 최대 200개의 미발행된 이벤트 일괄 처리
        List<OutboxEvent> batch = repo.findTop200ByPublishedFalseOrderByCreatedAtAsc();
        log.info("총 {}개의 미발행된 이벤트를 발견했습니다.", batch.size());
        if (batch.isEmpty()) return;
        // 발견한 미발행 이벤트를 전부 전송
        for (OutboxEvent e : batch) {
            try {
                    kafka.send(authEventsTopic, String.valueOf(e.getAggregateId()), e.getPayload()).get();
                    e.setPublished(true);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Kafka 전송 중 인터럽트 발생", ex);
                } catch (ExecutionException ex) {
                    throw new IllegalStateException("Kafka 전송 실패", ex.getCause());
                }
            }
        // JPA @Transactional 이므로 여기서 커밋
        log.info("총 {}개의 이벤트가 발행됐습니다.", batch.size());
    }
}
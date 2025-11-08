package com.sampoom.auth.api.auth.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sampoom.auth.api.auth.entity.AuthUser;
import com.sampoom.auth.api.auth.repository.AuthUserRepository;
import com.sampoom.auth.api.auth.event.AuthWarmupEvent;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthWarmupPublisher {

    private final KafkaTemplate<String, String> kafka;
    private final ObjectMapper objectMapper;
    private final AuthUserRepository authUserRepo;

    @Value("${app.topics.auth-events:auth-events}")
    private String userEventsTopic;

    @PostConstruct
    public void publishWarmupOnStartup() {
        try {
            List<AuthUser> users = authUserRepo.findAll();
            AuthWarmupEvent evt = AuthWarmupEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .eventType("AuthSystemWarmup")
                    .occurredAt(OffsetDateTime.now().toString())
                    .payload(users.stream()
                            .map(u -> new AuthWarmupEvent.AuthUserPayload(
                                    u.getId(),
                                    u.getEmail(),
                                    u.getRole(),
                                    u.getVersion(),
                                    u.getCreatedAt(),
                                    u.getUpdatedAt()
                            ))
                            .toList())
                    .build();

            String payload = objectMapper.writeValueAsString(evt);
            kafka.send(userEventsTopic, payload);
            log.info("AuthSystemWarmup 이벤트 발행 완료 (topic={})", userEventsTopic);
        } catch (Exception e) {
            log.error("AuthSystemWarmup 이벤트 발행 실패", e);
        }
    }
}

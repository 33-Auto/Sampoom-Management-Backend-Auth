package com.sampoom.auth.api.auth.outbox;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "outbox_event", indexes = {
        @Index(name = "idx_outbox_published", columnList = "published"),
        @Index(name = "idx_outbox_created_at", columnList = "createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OutboxEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String eventType;              // ex) 회원 생성

    @Column(nullable = false)
    private Long aggregateId;              // ex) userId

    @Lob @Column(nullable = false)
    private String payload;                // JSON

    @Builder.Default
    private boolean published = false;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @PrePersist
    void prePersist() { this.createdAt = LocalDateTime.now(); }
}
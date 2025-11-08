package com.sampoom.auth.api.auth.event;

import com.sampoom.auth.common.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthWarmupEvent {
    private String eventId;
    private String eventType; // 항상 "AuthSystemWarmup"
    private String occurredAt;
    private List<AuthUserPayload> payload;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthUserPayload {
        private Long userId;
        private String email;
        private Role role;
        private Long version;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
    }
}

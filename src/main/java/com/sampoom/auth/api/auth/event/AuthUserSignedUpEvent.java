package com.sampoom.auth.api.auth.event;

import com.sampoom.auth.common.entity.Role;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;

@Getter @Builder @NoArgsConstructor @AllArgsConstructor
public class AuthUserSignedUpEvent {
    @NotNull
    private String eventId;
    @NotNull
    private String eventType;      // "UserSignedUp"
    @Builder.Default
    private Long version=1L;
    @NotNull
    private String occurredAt;     // ISO-8601
    @NotNull
    private Payload payload;

    @Getter @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Payload {
        // User(Auth)
        @NotNull
        private Long userId;
        @NotNull
        private String email;
        @NotNull
        private Role role;
        @NotNull
        private LocalDateTime createdAt;
    }
}

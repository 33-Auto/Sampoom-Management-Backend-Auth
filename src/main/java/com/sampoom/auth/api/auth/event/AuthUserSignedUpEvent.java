package com.sampoom.auth.api.auth.event;

import com.sampoom.auth.common.entity.MemberRole;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;

@Getter @Builder @NoArgsConstructor @AllArgsConstructor
public class AuthUserSignedUpEvent {
    private String eventId;
    private String eventType;      // "AuthUserSignedUp"
    private Long version;
    private String occurredAt;
    private Payload payload;

    @Getter @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Payload {
        // User(Auth)
        @NotNull
        private Long userId;
        @NotNull
        private String email;
        @NotNull
        private MemberRole role;
        @NotNull
        private LocalDateTime createdAt;
    }
}

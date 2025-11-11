package com.sampoom.auth.api.auth.event;

import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.Workspace;
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
        private Workspace workspace;
        @NotNull
        private Role role;
        @NotNull
        private LocalDateTime createdAt;
    }
}

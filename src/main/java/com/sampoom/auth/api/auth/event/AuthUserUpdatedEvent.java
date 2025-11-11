package com.sampoom.auth.api.auth.event;

import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.Workspace;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthUserUpdatedEvent {
    private String eventId;
    private String eventType;      // "AuthUserUpdated"
    private Long version;
    private String occurredAt;     // ISO-8601
    private Payload payload;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
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
        private LocalDateTime updatedAt;
    }

}

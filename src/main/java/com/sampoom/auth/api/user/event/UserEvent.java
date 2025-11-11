package com.sampoom.auth.api.user.event;

import com.sampoom.auth.common.entity.EmployeeStatus;
import com.sampoom.auth.common.entity.Workspace;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEvent {
    private String eventId;
    private String eventType;      // "EmployeeUpdated"
    private Long version;
    private String occurredAt;
    private Payload payload;

    @Getter @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Payload {
        // User(Auth)
        @NotNull
        private Long userId;
        @NotNull
        private EmployeeStatus employeeStatus;

        private LocalDateTime updatedAt;
    }
}

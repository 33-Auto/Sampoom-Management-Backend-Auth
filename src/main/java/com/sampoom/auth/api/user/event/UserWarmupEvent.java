package com.sampoom.auth.api.user.event;
import com.sampoom.auth.common.entity.EmployeeStatus;
import com.sampoom.auth.common.entity.Workspace;
import jakarta.validation.constraints.NotNull;
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
public class UserWarmupEvent {
    private String eventId;
    private String eventType; // "UserSystemWarmup"
    private String occurredAt;
    private List<UserPayload> prodMembers;
    private List<UserPayload> invenMembers;
    private List<UserPayload> agencyMembers;
    private List<UserPayload> purchaseMembers;
    private List<UserPayload> salesMembers;
    private List<UserPayload> mdMembers;
    private List<UserPayload> hrMembers;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserPayload {
        @NotNull
        private Long userId;
        @NotNull
        private EmployeeStatus employeeStatus;

        private Long version;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
    }
}

package com.sampoom.auth.api.user.event;
import com.sampoom.auth.common.entity.EmployeeStatus;
import com.sampoom.auth.common.entity.Workspace;
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
    private List<UserPayload> factoryEmployees;
    private List<UserPayload> warehouseEmployees;
    private List<UserPayload> agencyEmployees;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserPayload {
        private Long userId;
        private Workspace workspace;
        private EmployeeStatus employeeStatus;
        private Long version;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
    }
}

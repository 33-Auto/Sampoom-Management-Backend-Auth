package com.sampoom.auth.api.user.entity;

import com.sampoom.auth.common.entity.BaseTimeEntity;
import com.sampoom.auth.common.entity.EmployeeStatus;
import com.sampoom.auth.common.entity.Workspace;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Entity
@Table(name = "user_projection")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class UserProjection extends BaseTimeEntity {
    @Id
    private Long userId;

    @Enumerated(EnumType.STRING)
    private Workspace workspace;

    @Enumerated(EnumType.STRING)
    private EmployeeStatus employeeStatus;

    private String lastEventId;

    @Column(nullable=false)
    private Long version;

    private OffsetDateTime sourceUpdatedAt;

}

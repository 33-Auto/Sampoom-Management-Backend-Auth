package com.sampoom.auth.api.auth.internal.dto;

import com.sampoom.auth.common.entity.MemberRole;
import com.sampoom.auth.common.entity.Position;
import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupUser {
    private Long userId;       // Auth에서 생성한 userId
    private String userName;   // 사용자 이름
    private MemberRole role;         // 근무지(대리점, 창고, 공장 등)
    private String branch;     // 지점명
    private Position position;   // 직책
}
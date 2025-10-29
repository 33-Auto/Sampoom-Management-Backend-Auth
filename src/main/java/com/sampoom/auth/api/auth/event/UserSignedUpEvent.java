package com.sampoom.auth.api.auth.event;

import lombok.*;

@Getter @Builder @NoArgsConstructor @AllArgsConstructor
public class UserSignedUpEvent {
    private String eventType;      // "UserSignup"
    private String occurredAt;     // ISO-8601
    private Payload payload;

    @Getter @Builder @NoArgsConstructor @AllArgsConstructor
    public static class Payload {
        // User(Auth)
        private Long userId;
        private String email;
        private String role;
        // User(Profile)
        private String userName;   // User 테이블에 복제
        // Employee
        private String workspace;  // FACTORY/WAREHOUSE/AGENCY
        private String branch;     // 지점(조직 매핑 키)
        private String position;   // 직급 (조직 Employee에 사용)
    }
}

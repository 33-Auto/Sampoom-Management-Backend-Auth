package com.sampoom.auth.common.entity;

public enum Role {
    // 통합 관리자: 모든 일반 관리자의 관리에 접근 가능
    ADMIN,

    // 일반 관리자: 자신에 해당하는 관리만 접근 가능
    MD,             // 기준 정보 관리
    SALES,          // 판매 관리
    INVENTORY,      // 재고 관리
    PRODUCTION,     // 생산 관리
    PURCHASE,       // 구매 관리
    HR,             // 인사 관리
}

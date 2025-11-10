package com.sampoom.auth.common.entity;

public enum Role {
    // 통합 관리자
    ADMIN,
    // 웹
    MD,           // 기준 정보 관리 부서
    SALES,        // 판매 관리 부서
    INVENTORY,    // 재고 관리 부서
    PRODUCTION,   // 생산 관리 부서
    PURCHASE,     // 구매 관리 부서
    HR,           // 인사 관리 부서
    // 앱
    AGENCY      // 대리점
}

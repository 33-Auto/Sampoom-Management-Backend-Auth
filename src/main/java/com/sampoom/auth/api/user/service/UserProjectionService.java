package com.sampoom.auth.api.user.service;

import com.sampoom.auth.api.user.entity.UserProjection;
import com.sampoom.auth.api.user.event.UserEvent;
import com.sampoom.auth.api.user.event.UserWarmupEvent;
import com.sampoom.auth.api.user.repository.UserProjectionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserProjectionService {

    private final UserProjectionRepository repo;

    @Transactional
    public void apply(UserEvent e) {
        final Long userId = e.getPayload().getUserId();
        final Long incomingVer = nvl(e.getVersion(), 0L);

        UserProjection projection = repo.findByUserId(userId).orElse(null);

        // 멱등 처리: 같은 이벤트 두 번 들어오면 무시
        if (projection != null && e.getEventId() != null && projection.getLastEventId() != null) {
            if (projection.getLastEventId().equals(e.getEventId())) {
                log.debug("[UserProjection] 중복 이벤트 무시: {}", e.getEventId());
                return;
            }
        }

        // 역순 이벤트 차단 (버전 낮은 이벤트는 무시)
        if (projection != null && incomingVer <= nvl(projection.getVersion(), 0L)) {
            log.debug("[UserProjection] 버전 역순 이벤트 무시: eventVer={} < storedVer={}", incomingVer, projection.getVersion());
            return;
        }

        switch (e.getEventType()) {
            case "EmployeeUpdated":
                upsert(projection, e, incomingVer);
                break;
            default:
                log.warn("Unknown eventType: {}", e.getEventType());
                break;
        }
    }

    private void upsert(UserProjection existing, UserEvent e, Long ver) {
        UserEvent.Payload p = e.getPayload();

        UserProjection next = (existing == null)
                ? UserProjection.builder()
                .userId(p.getUserId())
                .workspace(p.getWorkspace())
                .employeeStatus(p.getEmployeeStatus())
                .lastEventId(e.getEventId())
                .sourceUpdatedAt(parseOffset(String.valueOf(p.getUpdatedAt())))
                .version(ver)
                .build()
                : existing.toBuilder()
                .workspace(p.getWorkspace())
                .employeeStatus(p.getEmployeeStatus())
                .lastEventId(e.getEventId())
                .sourceUpdatedAt(parseOffset(String.valueOf(p.getUpdatedAt())))
                .version(ver)
                .build();

        repo.save(next);
        log.info("[UserProjection] upsert 완료: userId={}, status={}, ver={}",
                p.getUserId(), p.getEmployeeStatus(), ver);
    }

    @Transactional
    public void rebuildFromWarmup(UserWarmupEvent event) {
        log.info("♻️ [UserProjectionService] Warmup 재구성 시작");
        repo.deleteAllInBatch();

        var all = new ArrayList<UserWarmupEvent.UserPayload>();
        all.addAll(event.getFactoryEmployees());
        all.addAll(event.getWarehouseEmployees());
        all.addAll(event.getAgencyEmployees());

        for (var p : all) {
            UserProjection projection = UserProjection.builder()
                    .userId(p.getUserId())
                    .workspace(p.getWorkspace())
                    .employeeStatus(p.getEmployeeStatus())
                    .version(p.getVersion())
                    .lastEventId(event.getEventId())
                    .sourceUpdatedAt(parseOffset(String.valueOf(p.getCreatedAt())))
                    .build();
            repo.save(projection);
        }

        log.info("[UserProjectionService] Warmup 완료 ({}건)", repo.count());
    }

    private OffsetDateTime parseOffset(String iso) {
        if (iso == null || iso.isBlank()) return null;
        try {
            return OffsetDateTime.parse(iso);
        } catch (Exception ex) {
            return LocalDateTime.parse(iso).atOffset(ZoneOffset.ofHours(9));
        }
    }

    private long nvl(Long v, long d) {
        return v == null ? d : v;
    }
}

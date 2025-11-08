package com.sampoom.auth.api.user.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sampoom.auth.api.user.event.UserWarmupEvent;
import com.sampoom.auth.common.exception.InternalServerErrorException;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.api.user.event.UserEvent;
import com.sampoom.auth.api.user.service.UserProjectionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.KafkaException;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserEventHandler {

    private final ObjectMapper objectMapper;
    private final UserProjectionService userProjectionService;

    @KafkaListener(topics = "user-events",groupId = "user-events-auth-prod")
    public void authEventHandle(String message, Acknowledgment ack) {
        try {
            JsonNode root = objectMapper.readTree(message);
            String eventType = root.get("eventType").asText();
            switch (eventType) {
                case "EmployeeUpdated": {
                    UserEvent event = objectMapper.treeToValue(root, UserEvent.class);
                    userProjectionService.apply(event);
                    break;
                }

                case "UserSystemWarmup": {
                    UserWarmupEvent event = objectMapper.treeToValue(root, UserWarmupEvent.class);
                    log.info("UserSystemWarmup 이벤트 수신 → projection 전체 재구성 시작");
                    userProjectionService.rebuildFromWarmup(event);
                    break;
                }

                default:
                    log.warn("eventType: {}", eventType);
            }
            ack.acknowledge();
        }
        catch (JsonProcessingException ex) {
            log.error("[AuthUserEventHandler] 이벤트 포맷 오류: {}", message, ex);
            ack.acknowledge();
            throw new InternalServerErrorException(ErrorStatus.INVALID_EVENT_FORMAT);
        }
        catch (KafkaException ex) {
            log.error("[AuthUserEventHandler] Kafka 통신 실패", ex);
            throw new InternalServerErrorException(ErrorStatus.FAILED_CONNECTION_KAFKA);
        }
        catch (InternalServerErrorException e) {
            throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
        }
        catch (Exception e) {
            log.error("[AuthUserEventHandler] Kafka 이벤트 처리 실패", e);
            ack.acknowledge();
            throw new InternalServerErrorException(ErrorStatus.EVENT_PROCESSING_FAILED);
        }
    }
}

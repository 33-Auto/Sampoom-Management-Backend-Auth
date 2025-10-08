package com.sampoom.backend.auth.user.service;

import com.sampoom.backend.auth.common.response.ErrorStatus;
import com.sampoom.backend.auth.user.controller.dto.request.SignupRequest;
import com.sampoom.backend.auth.user.controller.dto.response.SignupResponse;
import com.sampoom.backend.auth.user.domain.User;
import com.sampoom.backend.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public SignupResponse signup(SignupRequest req) {
        if (userRepository.existsByEmail(req.getEmail())) {
            throw new IllegalArgumentException(ErrorStatus.ALREADY_REGISTER_EMAIL_EXCEPETION.getMessage());
        }

        User user = User.builder()
                .email(req.getEmail())
                .password(passwordEncoder.encode(req.getPassword()))
                .workspace(req.getWorkspace())
                .location(req.getLocation())
                .branch(req.getBranch())
                .name(req.getName())
                .position(req.getPosition())
                .build(); // 자동 ROLE_USER, createdAt/updatedAt

        User saved = userRepository.save(user);

        return SignupResponse.builder()
                .userId(saved.getId())
                .username(saved.getName())
                .email(saved.getEmail())
                .build();
    }
}
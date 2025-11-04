package com.sampoom.auth.api.auth.internal.fallback;

import com.sampoom.auth.api.auth.internal.dto.LoginUserRequest;
import com.sampoom.auth.api.auth.internal.dto.LoginUserResponse;
import com.sampoom.auth.api.auth.internal.dto.SignupUser;
import com.sampoom.auth.common.exception.InternalServerErrorException;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.api.auth.internal.client.UserClient;
import com.sampoom.auth.common.response.ErrorStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;

@Component
public class UserClientFallback implements UserClient {
    @Override
    public void createProfile(@RequestBody SignupUser req) {
        throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
    }

    @Override
    public LoginUserResponse verifyWorkspace(@RequestBody LoginUserRequest req) {
        throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
    }
}

package com.sampoom.auth.api.auth.utils;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

public class CookieUtils {
    public static void addAuthCookies(HttpServletResponse response, String access, String refresh, long accessTtl, long refreshTtl) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                ResponseCookie.from("ACCESS_TOKEN", access)
                        .httpOnly(true).secure(true).sameSite("None").path("/").maxAge(accessTtl).build().toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                ResponseCookie.from("REFRESH_TOKEN", refresh)
                        .httpOnly(true).secure(true).sameSite("None").path("/").maxAge(refreshTtl).build().toString());
    }

    public static void clearAuthCookies(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                ResponseCookie.from("ACCESS_TOKEN", "").httpOnly(true).secure(true).sameSite("None").path("/").maxAge(0).build().toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                ResponseCookie.from("REFRESH_TOKEN", "").httpOnly(true).secure(true).sameSite("None").path("/").maxAge(0).build().toString());
    }
}

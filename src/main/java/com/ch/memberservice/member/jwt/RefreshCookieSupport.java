package com.ch.memberservice.member.jwt;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;


@Slf4j
@Component
public class RefreshCookieSupport {

    @Value("${app.jwt.refresh-exp-seconds}") private long refreshExpSeconds;
    @Value("${app.jwt.refresh-cookie-path}") private String path;
    @Value("${app.jwt.refresh-cookie-secure}") private boolean secure;
    @Value("${app.jwt.refresh-cookie-samesite}") private String sameSite;

    /*-------------------------------------------------------------------------------------------
     refresh token용 쿠키 생성(쿠키 생성은 js에서만 할 수 있는 것이 아니다.)
     ------------------------------------------------------------------------------------------*/
    public void setRefreshCookie(HttpServletResponse response, String refreshToken) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)     // 이 속성을 true로 지정한 쿠키는 이 쿠키가 클라이언트에 전송되었을 경우, js로 접근이 불가능
                .secure(secure)      // https 실행 운영 시,  암호화된 데이터 방식을 씀 , http는 공부, 연구 목적
                .path(path)  // 브라우저가 요청 URL이 /api/auth로 시작할 때만 서버로 자동 전송 (/api/auth/**)
                                            // 제한 이유? 노출 최소화 (.재발급/로그아웃 API에서만 사용 )
                .maxAge(Duration.ofSeconds(refreshExpSeconds))
                /*
                    sameSite
                    1. Strict       : 브라우저는 같은 사이트 요청에서만 쿠키를 서버로 보낸다.
                    2. Lax          : 브라우저는 일부 안전한 요청에서만 쿠키를 서버로 보낸다.
                    3. None         : 브라우저는 모든 크로스 사이드 요청에서도 쿠키를 서버로 보낸다. 이때는 secure(true)
                 */
                .sameSite(sameSite)
                .build();

        // 헤더에 쿠키 추가
        // Set-Cookie: 헤더의 이름 (통로)
        // refreshToken: 쿠키의 이름 (Key)
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /*-------------------------------------------------------------------------------------------
     refresh token용 쿠키 삭제 - 쿠키는 삭제하는 방법이 따로 없으며 그냥 maxAge = 0으로 내려주면 됨. 즉, 만료 지시하면 됨
     ------------------------------------------------------------------------------------------*/
    public void deleteRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(secure)
                .path(path)
                .sameSite(sameSite)
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        log.debug("RefreshToken 쿠키 삭제");
    }

    /*-------------------------------------------------------------------------------------------
     refresh Token 꺼내기
     ------------------------------------------------------------------------------------------*/
    public Optional<String> readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null) return Optional.empty();

        return Arrays.stream(cookies)
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                // 순회하다가 첫 번째를 발견하면 멈춤
                .findFirst();
    }

}
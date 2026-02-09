package com.ch.memberservice.member.jwt;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

import java.util.Optional;

public class AccessTokenExtractor {

    private AccessTokenExtractor() {}

    public static Optional<String> extractBearerToken(HttpServletRequest request) {
        // Header의 표준이름인 Authorization으로 헤더 얻기
        /*
            front단에서도 header이름을 Authorization으로 맞췄다.
                 headers: {
                "Authorization": "Bearer " + accessToken,
                "Content-Type": "application/json"
            }
         */
        //String header = request.getHeader("Authorization");
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(header == null || !header.startsWith("Bearer ")) {   // 헤더가 없거나, Bearer로 시작하지 않으면 토큰 지참 안 한 걸로 알겠다.
            return Optional.empty();    // Optional에게 데이터가 없음을 알림
        }

         //String token = header.substring(7).trim();

        return Optional.of(header.substring("Bearer ".length()).trim());
    }
}

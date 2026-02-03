package com.ch.memberservice.member.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
    앞으로는 JWT를 발급받은 클라이언트가 매 요청마다 header안에 Authorization의 값으로 Bearer XXXXXXX 토큰을 지참하기 때문에
    이 JWT토큰이 유효하다면, 시큐리티의 SecurityContext에 로그인 인증회원이라는 기록을 저장하고, 원래 클라이언트가 원했던 API에
    접근할 수 있도록 허용!!
    But JWT가 문제가 있을 경우, 에러 메시지 처리를 수행
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /*
                 headers: {
                "Authorization": "Bearer " + accessToken,
                "Content-Type": "application/json"
            }
         */
        // 클라이언트의 헤더 추출
        String header = request.getHeader("Authorization");

        // 헤더에 Authorization이 없으면 SecurityContext에 로그인 인증회원이라는 기록을 저장하지 않음.
        // 아무것도 처리하지 않음..
        if(header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Token을 지참한 사용자의 경우...
        String token = header.substring(7).trim();  // Bearer와 혹시 모를 공백까지 제거한 순수 토큰만 꺼냄

        if(jwtTokenProvider.validateAccessToken(token)) {
            // 스프링 시큐리티에게 이 요청은 로그인 인증을 받았다는 사실을 알려줘야 함
            if(SecurityContextHolder.getContext().getAuthentication() == null) {    // 기존에 인증을 받은 적이 없는 유저라면(인증 정보가 없는 경우라면)
                // jwtProvider 안에 jwt token을 이용하여 Authentication Token을 얻어오는 메서드가 준비되어 있음
                Authentication auth = jwtTokenProvider.getAuthentication(token);
                // 이 등록을 하는 순간 스프링 인증회원이라는 것을 알게 되는 시점이므로, 가던 길을 가게 해줌.
                SecurityContextHolder.getContext().setAuthentication(auth);
                log.debug("필터 단계에서 JWT 검증 성공");
            }
        }
        filterChain.doFilter(request, response);
    }
}

package com.ch.memberservice.member.jwt;

import com.ch.memberservice.member.exception.JwtAuthenticationException;
import com.ch.memberservice.member.redis.RedisTokenStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
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
    private final RedisTokenStore redisTokenStore;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return "OPTIONS".equalsIgnoreCase(request.getMethod())
                || uri.startsWith("/api/auth/login")
                || uri.startsWith("/api/auth/logout")
                || uri.startsWith("/api/auth/refresh");     // 있다면
    }

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
        /*--------------------------------------------------------------------------------------
        1) 토큰이 존재하는가?
        --------------------------------------------------------------------------------------*/
        if(header == null || !header.startsWith("Bearer ")) {   // 헤더가 없거나, Bearer로 시작하지 않으면 토큰 지참 안 한 걸로 알겠다.
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7).trim();

        /*--------------------------------------------------------------------------------------
        2) 토큰이 유효한가?
            - 만료
            - 위조/변조/형식불일치
            - Access token 인지..
        --------------------------------------------------------------------------------------*/
        try {
            Claims claims = jwtTokenProvider.getClaims(token);

            String tokenType = claims.get("tokenType", String.class);
            // tokenType이 널일 수도 있으니 equals 앞이 "access"
            if(!"access".equals(tokenType)) {
                // 클라이언트의 브라우저에 이 에러 정보를 보내야 함...
                throw new JwtAuthenticationException("Access Token이 아님");
            }

            /*--------------------------------------------------------------------------------------
            3) 블랙리스트에 등록되어 있는지
            --------------------------------------------------------------------------------------*/
            String accessJti = claims.getId();

            if(accessJti != null && redisTokenStore.isAccessTokenBlacklisted(accessJti)) {
                // 이 에러 정보를 클라이언트도 알아야 하므로, 추후 에러 응답처리 할 예정...
                throw new JwtAuthenticationException("사용할 수 없는 토큰(블랙리스트)");
            }

            // 유효한 토큰을 가진 자이므로, 보상...(서버의 api를 접근할 수 있는 보상)
            // 보상 == 스프링 시큐리티에게 인증이 성공된 회원이라는 것을 알려줌..
            if(SecurityContextHolder.getContext().getAuthentication() == null) {
                Authentication auth = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

            filterChain.doFilter(request, response);    // 원래 요청했던 그 api로 접근하게 해줌...

        } catch(ExpiredJwtException e) {
            // 만료 시 처리할 에러 응답 정보..
            throw new JwtAuthenticationException("만료된 토큰입니다");
            // .parseSignedClaims(token) in getClaims() 여기서 에러가 날 수 있음
        } catch (JwtException | IllegalArgumentException e) {
            // 위조/변조/형식오류/서명불일치

            // 개발자는 클라이언트의 브라우저에 적절한 에러 메시지...
            throw new JwtAuthenticationException("invalid token");
        }

    }
}

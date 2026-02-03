package com.ch.memberservice.member.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.sql.Date;
import java.time.Instant;
import java.util.Base64;
import java.util.stream.Collectors;

public class JwtTokenProvider {

    @Value("${app.jwt.secret")
    private String secret;

    @Value("${app.jwt.access-exp-seconds")
    private long accessExpSeconds;

    private SecretKey key;

    // 생성자 호출 이후에 호출하는 어노테이션 @PostContruct
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }


    /*-------------------------------------------------------------------------------------------
     토큰 발급 ( 로그인에 성공한 자의 정보를 이용해야  하므로, Authentication Token이 필요 )
     ------------------------------------------------------------------------------------------*/
    public String createAccessToken(Authentication auth) {
        Instant now = Instant.now();    // 현재 시간 구하기
        Instant exp = now.plusSeconds(accessExpSeconds);    // 만료 시간

        String roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(auth.getName())    // homepageId
                .claim("roles", roles)    // 주장 아니라 여기선 사실
                .claim("tokenType", "access")   // api 서버 접근용 토큰 (최대 생존 기간 15분으로 설정함)
                .issuedAt(Date.from(now))   // 토큰 발급 시간
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
}

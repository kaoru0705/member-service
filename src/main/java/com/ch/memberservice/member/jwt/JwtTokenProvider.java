package com.ch.memberservice.member.jwt;

import com.ch.memberservice.member.service.MemberDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.sql.Date;
import java.time.Instant;
import java.util.Base64;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-exp-seconds}")
    private long accessExpSeconds;

    private SecretKey key;

    private final MemberDetailsService memberDetailsService;

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

        // 권한 중 역할을 하나로 뭉침
        String roles = auth.getAuthorities().stream()
                // (auth) -> auth.getAuthority()
                .map(GrantedAuthority::getAuthority)
                //Collectors.joining(",")은 요소가 2개 이상일 때 "ROLE_USER,ROLE_ADMIN" MemberUserDetails에서 getAuthorities가 아직 ROLE_USER 고정이라 와닿진 않는다.
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .subject(auth.getName())    // homepageId formlogin에 경우, .usernameParameter("homepageId")
                .claim("roles", roles)    // 주장 아니라 여기선 사실
                .claim("tokenType", "access")   // api 서버 접근용 토큰 (최대 생존 기간 15분으로 설정함)
                .issuedAt(Date.from(now))   // 토큰 발급 시간
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
    /*-------------------------------------------------------------------------------------------
     AccessToken 유효성 검증
     ------------------------------------------------------------------------------------------*/
    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // 위변조 검증을 원하는 토큰을 매개변수로 넘김
    // 합쳐진 토큰을 getClaims를 통해 분해해서 반환
    public boolean validateAccessToken(String token) {
        try {
            Claims claims = getClaims(token);

            // token이 유효하다면 tokenType 에 "access"가 들어있을 것이다.
            // 유효하지 않다면 끄집어내는 게 불가능할 것이다.
            "access".equals(claims.get("tokenType", String.class)); // claims에서 데이터 꺼낼 때는 key값과 값에 대한 자료형, class
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }

    }

    /*-------------------------------------------------------------------------------------------
     토큰을 이용하여 Authentication Token 얻기
     ------------------------------------------------------------------------------------------*/
    public Authentication getAuthentication(String token) {
        // 토큰의 주인 즉, 회원의 id 꺼내기
        Claims claims = getClaims(token);
        String homepageId = claims.getSubject();    // 토큰에 넣은 회원 아이디 꺼내기

        UserDetails userDetails = memberDetailsService.loadUserByUsername(homepageId);

        // 원래는 로그인 성공한 이후, 스프링이 알아서 채워넣지만, 지금은 Jwt필터를 이용한 로그인 처리이므로, 개발자가 직접 진행
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

}

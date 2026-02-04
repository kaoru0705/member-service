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
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-exp-seconds}")
    private long accessExpSeconds;

    @Value("${app.jwt.refresh-exp-seconds}")
    private long refreshExpSeconds;


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

        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .id(jti)
                .subject(auth.getName())    // homepageId
                .claim("roles", roles)    // 주장 아니라 여기선 사실
                .claim("tokenType", "access")   // api 서버 접근용 토큰 (최대 생존 기간 15분으로 설정함)
                .issuedAt(Date.from(now))   // 토큰 발급 시간
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }
    /*-------------------------------------------------------------------------------------------
     RefreshToken 토큰 (AccessToken이 만료시간이 짧으므로, 이를 갱신하기 위한 토큰)
     ------------------------------------------------------------------------------------------*/
    public String createRefreshToken(Long memberId) {
        Instant now = Instant.now();    // 현재 시간 구하기
        Instant exp = now.plusSeconds(refreshExpSeconds);    // 만료 시간

        // Universally Unique IDentifier -32자리  전세계적으로 겹칠 확률이 거의 없음
        String jti = UUID.randomUUID().toString();


        return Jwts.builder()
                .id(jti)// 고유값(중복될 가능성이 거의 없는 수준의 고유값)
                .subject(Long.toString(memberId))    // 우리의 경우 OAuth2로 로그인한 유저는 homepageId가 null일 수 있기 때문...
                .claim("tokenType", "refresh")
                .issuedAt(Date.from(now))   // 토큰 발급 시간
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /*-------------------------------------------------------------------------------------------
     AccessToken 유효성 검증
     getClaims()를 하는 중 위조된 경우 Exception 발생
     ------------------------------------------------------------------------------------------*/

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // subject 반환 == memberId or homepageId
    public String getSubject(String token) {
        return getClaims(token).getSubject();
    }

    // JTI 반환
    public String getJti(String token) {
        return getClaims(token).getId();
    }

    // Exp 반환
    public Instant getExp(String token) {
        return getClaims(token).getExpiration().toInstant();
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

    /*----------------------------------------------------------
     Refresh 토큰 유효성 검증
     ----------------------------------------------------------*/
    public boolean validateRefreshToken(String token) {
        try {
            Claims claims = getClaims(token);
            return "refresh".equals(claims.get("tokenType", String.class));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /*-------------------------------------------------------------------------------------------
     토큰을 이용하여 Authentication Token 얻기
     당연한 얘기지만 이미 과거에 로그인 한 사람이니 토큰으로 정보를 가져올 수 있는 것이다.
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

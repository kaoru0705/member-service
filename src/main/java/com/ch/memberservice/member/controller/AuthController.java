package com.ch.memberservice.member.controller;

import com.ch.memberservice.member.dto.LoginResponse;
import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.dto.MemberResponse;
import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.MemberUserDetails;
import com.ch.memberservice.member.jwt.AccessTokenExtractor;
import com.ch.memberservice.member.jwt.JwtTokenProvider;
import com.ch.memberservice.member.jwt.RefreshCookieSupport;
import com.ch.memberservice.member.redis.RedisTokenStore;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
// @Service같은 걸로 등록되어 있어야 RequiredArgsContructor가 작동한다.
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenStore redisTokenStore;

    private final RefreshCookieSupport refreshCookieSupport;

    @Value("${app.jwt.refresh-exp-seconds}")
    private long refreshExpSeconds;

    // 회원 임시 등록 (비번을 암호화하여 임시로 등록해보기)
    // 우회해서 등록하려면 Filter를 거치지만 예외로 허용시켜서(requestMatchers) 바로 AuthController로 가게 만들고
    // 스프링 시큐리티에서 사용하는 MemberDetailService가 아닌 우리만의 service로 Manager에 접근해야 한다.
    @PostMapping("/temp")
    public ResponseEntity<?> tempRegist(MemberRequest memberRequest) {

        log.debug("homepageId is {}", memberRequest.getHomepageId());
        log.debug("password is {}", memberRequest.getPassword());
        log.debug("name is {}", memberRequest.getName());

        return ResponseEntity.ok(memberService.regist(memberRequest));
    }

    /*-----------------------------------------------------------------------------------------
    로그인 요청 처리(스프링 필터체인의 요청을 받는 UsernamePasswordAuthenticationFilter를 거치지 않고
    직접 로그인 요청을 받는다. but AuthenticationManager에게 직접 일을 시켜보자)
    ------------------------------------------------------------------------------------------*/
    @PostMapping("/login")
    public ResponseEntity<?> login(MemberRequest memberRequest, HttpServletResponse response) {

        log.debug("로그인 요청 시 homepageId is {}", memberRequest.getHomepageId());
        log.debug("로그인 요청 시 password is {}", memberRequest.getPassword());

        // AuthenticationManaer 호출

        // authenticate(authentication) throws AuthenticationException;
        // Authentication Token을 구현한 구현체 - UsernamePasswordAuthenticationToken(Object principal, Object credentials)
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(memberRequest.getHomepageId(), memberRequest.getPassword()));
        // MemberUserDetails에는 password도 들어있으므로
        MemberUserDetails userDetails = (MemberUserDetails) auth.getPrincipal();
        Member member = userDetails.getMember();

        if (auth == null) {
            log.debug("로그인 인증 실패");
        }

        log.debug("로그인 인증 성공");

        // AccessToken 발급
        String accessToken = jwtTokenProvider.createAccessToken(auth);
        String refreshToken = jwtTokenProvider.createRefreshToken(member.getMemberId());

        // redis에 저장
        String refreshJti = jwtTokenProvider.getJti(refreshToken);
        redisTokenStore.saveRefreshToken(member.getMemberId(), refreshJti, refreshToken, refreshExpSeconds);

        /*
            쿠키 내려주기 refreshToken cookie로 넘기기
            setRefreshCookie 참조
            refreshToken은 개발자가 코드로 직접 넣어준 게 아니라, 브라우저가 자동으로 넣어준 것입니다.
            이때 서버는 응답 헤더에 Set-Cookie: refreshToken=xxxx; HttpOnly; Path=/api/auth; ... 라는 내용을 실어서 보냅니다.
            브라우저는 이 헤더를 읽고 "아, 이 데이터는 내 전용 금고(Cookie Storage)에 넣어두고, 나중에 /api/auth로 요청 보낼 때마다 꺼내서 써야겠다"라고 저장합니다.
         */
        refreshCookieSupport.setRefreshCookie(response, refreshToken);


        // LoginResponse 쓰는 이유? 이래야 ResponseBody로 accessToken 객체 형태로 보내서 json으로 바꿀 수 있다. accessToken을 body로 넘기고 있다.
        return ResponseEntity.ok(new LoginResponse("Bearer", accessToken));
    }

    /*-----------------------------------------------------------------------------------------
    로그아웃 요청 처리
    - 지금 가지고 있는 토큰이 정상이라면 전부 무효화하고, 정상이 아니어도 그냥 로그아웃 요청 만으로도
    성공으로 처리한다. -> 로그아웃이면 그냥 전부 무효화하겠다.
    ------------------------------------------------------------------------------------------*/
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        /*--------------------------------------------------------
        1) refresh 토큰이 존재하면 폐기
        --------------------------------------------------------*/
        /*
            반환값이 Optional 일 경우 이 객체의 메서드 중 ifPresent()가 지원됨
            ifPresent()는 객체가 존재할 때만 동작, 존재하지 않으면 호출되지 않음...
            어떤 대상이 존재할 때만 코드를 실행하고 싶을 때 유용...
            HttpServletRequest 객체 안에는 브라우저가 자동으로 넣어준 모든 헤더 정보가 들어있습니다.
            readCookie 메서드는 그 수많은 헤더 중 Cookie라는 이름의 헤더를 찾아 그 안에서 refreshToken이라는 글자를 찾아내는 것입니다.
         */
        refreshCookieSupport.readCookie(request, "refreshToken").ifPresent(rt -> {
            try {
                if (jwtTokenProvider.validateRefreshToken(rt)) {  // 토큰이 유효하다면...
                    // redis에서 삭제
                    Long memberId = Long.parseLong(jwtTokenProvider.getSubject(rt));
                    String jti = jwtTokenProvider.getJti(rt);
                    redisTokenStore.revokeRefreshToken(memberId, jti);  // refresh token 제거
                }
            } catch (Exception e) {
                // 로그아웃 과정에서 실패가 발생하는 이유는 그 수단이 이미 그 로그아웃 수단이 깨졌다가 만료되거나, 폐기된 상태이기 때문에
                // 어차피 로그아웃 실패라 할지라도 이미 로그인을 유지할 수 없는 상태이기 때문에 예외 처리의 실익이 없다.
                // 사용자에게 알려줄 의미도 없다.
            }
        });

        /*--------------------------------------------------------
        2) 블랙리스트 등록(지금 쓰고 있는 Access Token을 즉시 무효로 만들어서, 아직 만료되지 않았어도 다시는 못 쓰게 함)
        --------------------------------------------------------*/
        AccessTokenExtractor.extractBearerToken(request).ifPresent(acc -> {

            try {
                if(jwtTokenProvider.validateAccessToken(acc)) {
                    String jti = jwtTokenProvider.getJti(acc);
                    Instant exp = jwtTokenProvider.getExp(acc);
                    // 토큰의 만료 시각에서 지금 시각을 빼서 남아있는 초를 구하되, 음수가 나오면 0으로 하자
                    long ttl = Math.max(0, exp.getEpochSecond() - Instant.now().getEpochSecond());
                    redisTokenStore.blackListAccessToken(jti, ttl);
                }
            } catch (Exception ignore) {
            }
        });

        /*--------------------------------------------------------
        3) 쿠키 제거
        --------------------------------------------------------*/
        refreshCookieSupport.deleteRefreshCookie(response);

        return ResponseEntity.ok(Map.of("message", "로그아웃됨"));
    }


    /*-----------------------------------------------------------------------------------------
    로그인해야 서비스 받을 수 있는 보호된 API

    SecurityContextHolder.getContext().setAuthentication(auth); in JwtAuthFilter 여기서 저장된 게 Authentication auth에 주입된다.
    ------------------------------------------------------------------------------------------*/
    @GetMapping("/me")
    public Map<String, Object> getMyInfo(Authentication auth) {

        // Authentication 들어있는 Principal을 꺼내서 사용정보로 제공
        MemberUserDetails memberUserDetails = (MemberUserDetails) auth.getPrincipal();
        //log.debug("auth.getPassword in getMyInfo {}", memberUserDetails.getPassword());

        return Map.of("name", memberUserDetails.getUsername());
    }

    /*-----------------------------------------------------------------------------------------
    리액트 프론트에서 코드가 전송되면, 이 코드를 이용하여 redis에서 AccessToken을 찾아 반환
    ------------------------------------------------------------------------------------------*/
    @PostMapping("/oauth2/exchange")
    public ResponseEntity<?> exchange(@RequestParam String code) {

        String accessToken = redisTokenStore.consumeCode(code).orElseThrow(() -> new IllegalArgumentException("Invalid code"));

        return ResponseEntity.ok(Map.of(
                "tokenType", "Bearer ",
                "accessToken", accessToken
        ));
    }

    @ExceptionHandler(AuthenticationException.class)
    public String handle(AuthenticationException e) {
        log.debug("인증 실패했네요 ㅜㅜ");

        return e.getMessage();
    }
}

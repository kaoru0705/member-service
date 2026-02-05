package com.ch.memberservice.member.oauth2;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.jwt.JwtTokenProvider;
import com.ch.memberservice.member.jwt.RefreshCookieSupport;
import com.ch.memberservice.member.redis.RedisTokenStore;
import com.ch.memberservice.member.repository.MemberRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/*
    OAuth2 인증 직후 호출되는 핸들러 클래스

    [ 역할/목적 ]
    1) OAuth2AuthenticationToken 에서 사용할 값 결정
    2) Access/Refresh 발급
    3)

    OAuth2로그인은 프론트에서 location.href로 authorization url을 달라고하는 동기인데 jwtAccessToken은 getWriter로 바디에 쓰고 있으므로 그게 프론트에 노출이된다.
    따라서 임시코드 1분짜리를 레디스로 발급하고 클라이언트에게 줘서 그걸로 redirect를 한다.


 */

@Component
@RequiredArgsConstructor
public class OAuth2JwtSuccessHandler implements AuthenticationSuccessHandler {

    @Value("${app.jwt.refresh-exp-seconds}")
    private long refreshExpSeconds;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final RedisTokenStore redisTokenStore;
    private final RefreshCookieSupport refreshCookieSupport;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 사용자 정보가 넘어오지 않으면, 에러...
        if(!(authentication instanceof OAuth2AuthenticationToken authenticationToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 authentication required");
            return;
        }

        String registrationId = authenticationToken.getAuthorizedClientRegistrationId();
        Map<String, Object> attrs = ((OAuth2User)authenticationToken.getPrincipal()).getAttributes();

        OAuth2UserInfo info = OAuth2UserInfoFactory.from(registrationId, attrs);

        // 우리 데이터베이스에서 회원 정보 가져오기
        Member member = memberRepository.findByProvider_ProviderNameAndOpenId(registrationId, info.openId())
                .orElseThrow(() -> new IllegalStateException("해당하는 사용자 정보를 찾을 수 없어요"));

        // Access JWT 발급
        String accessToken = jwtTokenProvider.createAccessToken(
           new UsernamePasswordAuthenticationToken(Long.toString(member.getMemberId()), null, List.of(new SimpleGrantedAuthority("ROLE_USER")))
        );

        // Refresh 발급
        String refreshToken = jwtTokenProvider.createRefreshToken(member.getMemberId());

        // JTI
        String jti = jwtTokenProvider.getJti(refreshToken);

        // redis 저장
        redisTokenStore.saveRefreshToken(member.getMemberId(), jti, refreshToken, refreshExpSeconds);

        // refresh token 쿠키 세팅
        refreshCookieSupport.setRefreshCookie(response, refreshToken);


        /*
            클라이언트 브라우저가 SNS 요청 자체를 비동기 방식이 아닌 location.href = "" 로 접근하므로 (즉, 동기방식)
            서버가 이에 대한 응답을 바디로 전송하면, 브라우저 화면에 데이터가 출력되어 버린다.

            해결책? 클라이언트가 비동기방식으로 임시코드를 요청하면, 서버가 잠시 보관하고 있었던 accesstoken을 발급하면 됨..

            [AccessToken -- Code 교환방식 ]

         */
        String code = UUID.randomUUID().toString();     // 임시코드 생성

        // redis에 저장형식 oauth2:code:UUID AccessToken
        redisTokenStore.saveTempCode(code, accessToken, 60);

        // 클라이언트로 하여금 지정한 URL로 리다이렉트 하라고 명령...
        // State Code_FOUND: 요청은 정상적으로 처리되었으나, 응답 결과를 다른 URL에 있으니 그 URL로 다시 요청해!
        response.setStatus(HttpServletResponse.SC_FOUND);
        // encodeURIComponent와 비슷한 URLEncoder
        response.setHeader(HttpHeaders.LOCATION, frontendUrl + "/oauth/callback?code=" + URLEncoder.encode(code, StandardCharsets.UTF_8));
        // response.getWriter().write("액세스 토큰 " + accessToken);

    }
}

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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

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

        response.getWriter().write("액세스 토큰 " + accessToken);

    }
}

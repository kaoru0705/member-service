package com.ch.memberservice.member.oauth2;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.Provider;
import com.ch.memberservice.member.redis.RedisTokenStore;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.repository.ProviderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*
    [역할 / 목적]
        -   OAuth2 로그인 과정에서 UserInfo 를 기반으로 우리 서비스의 회원과 연결하고, 이후 Security 사용할
            OAuth2User를 반환해야 함
 */

@Service
@RequiredArgsConstructor
// DefaultOAuth2Userservice는 naver랑 카카오만 먹힌다?
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final ProviderRepository providerRepository;
    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 회원가입을 위한 provider 정보 추출 yaml
        String registrationId = userRequest.getClientRegistration().getRegistrationId();    // google, naver, kakao

        // 구글은 지원 객체가 다르므로, 여기서 google일 경우 코드 진행을 막자
        if("google".equals(registrationId)) {
            return super.loadUser(userRequest);
        }

        OAuth2UserInfo info = OAuth2UserInfoFactory.from(registrationId, oAuth2User.getAttributes());

        // registrationId는 String일 뿐이므로, Provider entity 직접 만들어야 함
        Provider provider = providerRepository.findByProviderName(registrationId).orElseThrow(() -> new OAuth2AuthenticationException("provider not found in db"));

        // 회원가입(우리 db에 회원이 없을 때만..)
        // orElseGet이란? 값이 있으면 그대로 쓰고, 없을 때만 람다를 실행하여 그 결과를 대신해
        Member member = memberRepository.findByProvider_ProviderNameAndOpenId(registrationId, info.openId())
                .orElseGet(() -> {
                    return memberRepository.save(
                            Member.createOAuth2(
                                    info.name(),
                                    info.email(),
                                    info.openId(),
                                    provider
                    ));
                });
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // 각 sns의 회원정보 맵
        Map<String, Object> attrs = new HashMap<>(oAuth2User.getAttributes());  // sub, response_id, id
        attrs.put("openId", info.openId()); // 개발자가 정의한 key-value 추가
        attrs.put("provider", registrationId);  // 개발자가 정의한 key-value 추가

        // 아래에서 반환되는 DefaultOAuth2User는 로그인 성공 시 Security가 Authentication Token(OAuth2Authentication Token) 안의 principal로 들어감...
        return new DefaultOAuth2User(authorities, attrs, "openId");
    }
}

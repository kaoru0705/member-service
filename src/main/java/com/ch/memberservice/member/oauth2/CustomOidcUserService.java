package com.ch.memberservice.member.oauth2;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.Provider;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.repository.ProviderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final ProviderRepository providerRepository;
    private final MemberRepository memberRepository;

    // delegate 위임한다
    private final OidcUserService  delegate = new OidcUserService();

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        OidcUser oidcUser = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();    // "google" 기대

        String openId = oidcUser.getSubject();  // OIDC 표준 고유 식별자: sub
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName();   // 없으면 null일 수 있음

        // registrationId는 String일 뿐이므로, Provider entity 직접 만들어야 함
        Provider provider = providerRepository.findByProviderName(registrationId).orElseThrow(() -> new OAuth2AuthenticationException("provider not found in db"));

        // 회원가입(우리 db에 회원이 없을 때만..)
        // orElseGet이란? 값이 있으면 그대로 쓰고, 없을 때만 람다를 실행하여 그 결과를 대신해
        Member member = memberRepository.findByProvider_ProviderNameAndOpenId(registrationId, openId)
                .orElseGet(() -> {
                    return memberRepository.save(
                            Member.createOAuth2(
                                    name,
                                    email,
                                    openId,
                                    provider
                            ));
                });

        return oidcUser;
    }
}

package com.ch.memberservice.member.oauth2;

import java.util.Map;

/*
    registartionId에 따라 즉, provider에 따라서 적절한 UserInfo 구현체를 생성
    이유, 장점 - CustomOAuth2UserService 코드가 공급자별로 if/else 사용하게 됨을 방지
*/
public class OAuth2UserInfoFactory {
    private OAuth2UserInfoFactory() {}

    // 이 메서드를 호출하려면, 공급자명(google, naver, kaao)  그 공급자에 해당하는 맴 데이터를 넘겨야 함
    public static OAuth2UserInfo from(String registrationId, Map<String, Object> attr) {
        return switch(registrationId) {
            case "google" -> new GoogleUserInfo(attr);
            case "naver" -> new NaverUserInfo(attr);
            case "kakao" ->  new KakaoUserInfo(attr);
            default -> throw new IllegalArgumentException("지원되지 않는 공급자명 " + registrationId);
        };
    }
}

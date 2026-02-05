package com.ch.memberservice.member.oauth2;


import java.util.Map;

/*
    Google OAUth2 사용자 정보 정규화
    -   토큰 취득 후, 사용자 정보를 우리 애플리케이션에 provider가 전송할 때,  사용자 정보를
        OAuth2라는 객체로 감싸서 Service 객체로 전달된다.
        이때, Provier 사업자마다 정보형태가 다르므로, 이를 통일하기 위한 방법의 일부...
 */
public class GoogleUserInfo implements OAuth2UserInfo {

    // provider 데이터가 json으로 전송되므로, 이 json을 보관할 java 객체는 바로 Map이다.
    private final Map<String, Object> attr;

    public GoogleUserInfo(Map<String, Object> attr) {
        this.attr = attr;
    }

    @Override
    public String provider() {
        return "google";
    }

    @Override
    public String openId() {
        Object sub = attr.get("sub");
        return String.valueOf(sub);
    }

    @Override
    public String email() {
        Object email = attr.get("email");
        return String.valueOf(email);

    }

    @Override
    public String name() {
        Object name = attr.get("name");
        return String.valueOf(name);

    }
}

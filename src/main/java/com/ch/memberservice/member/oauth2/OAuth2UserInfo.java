package com.ch.memberservice.member.oauth2;

/*
    구글/네이버/카카오가 보내주는 사용자 정보를 우리 서비스에서 사용하기 쉽게(코드 깔끔목적)
    이 인터페이스를 이용한 정규화 과정을 거치면 추후 DefaultOAUth2UserService 작성 시 코드가 깔끔해짐
    공통(보편화)화 시켜 즉, 정규화 시키겠음
    ex) google - sub, naver - response.id, kakao - id   --> openId
 */
public interface OAuth2UserInfo {
    // 필수적인 추상메서드 정의
    String provider();
    String openId();
    String email();
    String name();
}

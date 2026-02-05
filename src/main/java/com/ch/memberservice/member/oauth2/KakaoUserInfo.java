package com.ch.memberservice.member.oauth2;

import java.util.Map;

/*
 {
     "id": 1234567890,
     "connected_at": "2024-01-01T12:00:00Z",
     "kakao_account": {
         "email": "zino@kakao.com",
         "email_needs_agreement": false,
         "profile": {
             "nickname": "지노",
             "profile_image_url": "http://k.kakaocdn.net/...",
             "thumbnail_image_url": "http://k.kakaocdn.net/..."
         }
     }
 }
*/
public class KakaoUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attrs;


    public KakaoUserInfo(Map<String, Object> attrs) {
        this.attrs = attrs;
    }

    @Override
    public String provider() {
        return "kakao";
    }

    @Override
    public String openId() {
        Object id=attrs.get("id");
        return String.valueOf(id);
    }

    @Override
    public String email() {
        Object account=attrs.get("kakao_account");

        Object email = ((Map<String,Object>)account).get("email");
        return String.valueOf(email);
    }

    @Override
    public String name() {
        Object account=attrs.get("kakao_account");
        Object profile = ((Map<String,Object>)account).get("profile");
        Object nickname=((Map<String,Object>)profile).get("nickname");

        return String.valueOf(nickname);
    }
}
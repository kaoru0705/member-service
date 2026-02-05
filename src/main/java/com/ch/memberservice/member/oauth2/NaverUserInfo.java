package com.ch.memberservice.member.oauth2;

import java.util.Map;

/*
  {
     "resultcode": "00",
     "message": "success",
     "response": {
         "id": "32742776",
         "email": "zino@naver.com",
         "name": "지노"
     }
 }
*/
public class NaverUserInfo implements  OAuth2UserInfo {

    private final Map<String, Object> response;

    public NaverUserInfo(Map<String, Object> attr) {
        Object res = attr.get("response");

        this.response = (Map<String, Object>) res;
    }

    @Override
    public String provider() {
        return "naver";
    }

    @Override
    public String openId() {
        Object id = response.get("id");
        return String.valueOf(id);
    }

    @Override
    public String email() {
        Object email = response.get("email");
        return String.valueOf(email);

    }

    @Override
    public String name() {
        Object name = response.get("name");
        return String.valueOf(name);

    }
}

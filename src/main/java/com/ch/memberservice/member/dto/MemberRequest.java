package com.ch.memberservice.member.dto;

import lombok.Getter;
import lombok.Setter;

// Entity는 보호되어야 하므로, 파라미터 등에 사용되지 않는다. 따라서 파라미터나 응답정보를
// 처리하기 위한 별도의 DTO 정의
@Getter
@Setter
public class MemberRequest {
    private String homepageId;
    private String password;
    private String name;

    public MemberRequest(String homepageId, String password, String name) {
        this.homepageId = homepageId;
        this.password = password;
        this.name = name;
    }
}

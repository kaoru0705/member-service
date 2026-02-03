package com.ch.memberservice.member.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberResponse {
    private String homepageId;
    private String name;

    public MemberResponse(String homepageId, String name) {
        this.homepageId = homepageId;
        this.name = name;
    }
}

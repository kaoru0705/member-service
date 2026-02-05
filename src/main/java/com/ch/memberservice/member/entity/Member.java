package com.ch.memberservice.member.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "member")
/*
@NoArgsConstructor는 파라미터가 없는 기본 생성자를 만들어줍니다. 그런데 이건 보통 **사용자(개발자)**가 쓰려고 만드는 게 아니라, JPA를 위해 만드는 것입니다.

JPA의 작동 방식: 데이터베이스에서 데이터를 조회해 올 때, JPA는 먼저 기본 생성자로 객체를 생성한 뒤 리플렉션 기술을 써서 값을 채워 넣습니다. 그래서 JPA 엔티티에는 기본 생성자가 필수입니다.
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long memberId;

    @Column(name = "homepage_id")
    private String homepageId;

    @Column(name = "password")
    private String password;

    @Column(name = "open_id")
    private String openId;

    @Column(name = "name")
    private String name;

    @Column(name = "email")
    private String email;

    @Column(name = "phone")
    private String phone;

    @Column(name = "regdate")
    private LocalDateTime regdate;

    @Column(name = "updated")
    private LocalDateTime updated;

    // FetchType.LAZY 바로 가져오지 않음 효율성
    /*
        FetchType.LAZY 로 설정하면? 연관된 entitty를 지금 당장 조회하지 말고, 실제로 필요할 때 DB 가져오라는 뜻
        예) memberRepository.findById() 호출 시점에  가져오지 않으며, 나중에 getProvider() 호출 시 가져옴
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "provider_id")
    private Provider provider;

    /* 추후 회원 생성을 팩토리 메서드를 통해 진행..*/
    public static Member create(String homepageId, String password, String name, String email) {
        Member member = new Member();
        member.homepageId = homepageId;
        member.password = password;
        member.name = name;
        member.email = email;

        return member;
    }

    /* 추후 OAuth2 회원 생성을 팩토리 메서드를 통해 진행..*/
    public static Member createOAuth2(String name, String email, String openId, Provider provider) {
        Member member = new Member();
        member.name = name;
        member.email = email;
        member.openId = openId;
        member.provider = provider;

        return member;
    }

}

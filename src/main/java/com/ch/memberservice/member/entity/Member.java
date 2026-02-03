package com.ch.memberservice.member.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "member")
/*
@NoArgsConstructor는 파라미터가 없는 기본 생성자를 만들어줍니다. 그런데 이건 보통 **사용자(개발자)**가 쓰려고 만드는 게 아니라, JPA를 위해 만드는 것입니다.

JPA의 작동 방식: 데이터베이스에서 데이터를 조회해 올 때, JPA는 먼저 기본 생성자로 객체를 생성한 뒤 리플렉션 기술을 써서 값을 채워 넣습니다. 그래서 JPA 엔티티에는 기본 생성자가 필수입니다.
 */
@NoArgsConstructor
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

    @Column(name = "name")
    private String name;

    public Member(String homepageId, String password, String name) {
        this.homepageId = homepageId;
        this.password = password;
        this.name = name;
    }
}

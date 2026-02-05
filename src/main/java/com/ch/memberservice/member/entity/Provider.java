package com.ch.memberservice.member.entity;


import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@Entity
// 외부에서 직접 new 하는 것을 막았다.
/*
    JPA라는 친구는 데이터베이스에서 데이터를 가져와 자바 객체로 만들 때, 내부적으로 **기본 생성자(매개변수가 없는 생성자)**를 호출합니다.
    JPA의 필수 조건: JPA는 리플렉션(Reflection)이라는 기술을 사용해 객체를 만듭니다. 이때 기본 생성자가 없으면 객체를 생성하지 못하고 에러를 던집니다.
    왜 하필 PROTECTED인가?: * public으로 열어두면 팀원들이나 미래의 내가 어디선가 new Provider()를 남발할 수 있습니다. 그렇게 되면 필수 값이 빠진 "빈 껍데기" 객체가 돌아다니게 되죠.
    private으로 닫으면? JPA가 접근을 못 해서 울기 시작합니다.
    결론: JPA는 허용하면서 외부의 무분별한 new는 막을 수 있는 가장 적절한 타협점이 바로 PROTECTED입니다.
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)  // JPA 를 위하여
@Table(name = "provider")
public class Provider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int providerId;

    @Column(name = "provider_name")
    private String providerName;

    // 개발자가 원하는 매개변수를 이용하여 원하는 방식의 생성을 하려면, 생성자를 이용하면 안 됨
    // 즉, 무언가 의미있는 생성을 위해서 생성자를 이용하면 안되는 원칙
    // 생성자를 대신할 수 있는 메서드를 통해 개발자가 원하는 형식의 데이터를 만들어야 함
    // 코드 주석에도 적혀 있듯이, 이건 **"생성자의 의도를 명확히 하고 생성을 캡슐화하기 위함"**입니다.
    // 이를 보통 정적 팩토리 메서드(Static Factory Method) 패턴이라고 불러요.
    public static Provider create(String providerName) {
        Provider p = new Provider();
        p.providerName = providerName;
        return p;
    }
}

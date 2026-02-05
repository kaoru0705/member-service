package com.ch.memberservice.member.repository;

import com.ch.memberservice.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // 회원의 홈페이지 아이디만으로, 회원정보를 가져오기 위한 메서드
    Optional<Member> findByHomepageId(String homepageId);

    /* 이미 회원가입되어 있는지 조회
    *  select * from member m join provider p
    * on m.provider_id = p.provider_id
    * and open_id = ?
    * */
    // Member entity의 Provider의 ProviderName과 openId로 Member를 찾겠다.
    Optional<Member> findByProvider_ProviderNameAndOpenId(String providerName, String openId);

}

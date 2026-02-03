package com.ch.memberservice.member.repository;

import com.ch.memberservice.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // 회원의 홈페이지 아이디만으로, 회원정보를 가져오기 위한 메서드
    Optional<Member> findByHomepageId(String homepageId);
}

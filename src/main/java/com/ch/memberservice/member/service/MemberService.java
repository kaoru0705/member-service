package com.ch.memberservice.member.service;

import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.repository.MemberRepository;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;

    // in SecurityConfig에서 빈 등록을 했으니 주입 가능
    private final PasswordEncoder passwordEncoder;

    public Member regist(MemberRequest memberRequest) {
        String homepageId = memberRequest.getHomepageId();
        String password = memberRequest.getPassword();
        String name = memberRequest.getName();

        Member member = Member.create(homepageId, passwordEncoder.encode(password), name, null);

        return memberRepository.save(member);
    }
}

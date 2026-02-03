package com.ch.memberservice.member.service;

import com.ch.memberservice.member.entity.Member;
import com.ch.memberservice.member.entity.MemberUserDetails;
import com.ch.memberservice.member.exception.MemberErrorCode;
import com.ch.memberservice.member.exception.MemberException;
import com.ch.memberservice.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/* 요청 처리 흐름에서 Provider에 의해 호출되는 서비스 메서드 */
@RequiredArgsConstructor
@Service
public class MemberDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String homepageId) throws UsernameNotFoundException {
        // 서비스는 회원을 검증하지 않는다. 즉, 회원의 비밀번호를 이용하여 조회하지 않는다..
        // 비밀번호 검증은 PasswordEncoder가 진행함
        // 회원이 존재할 경우 Member entity가 반환되지만, 시큐리티는 이해하지 못함.. 시큐리티는 한 회원에 대한 정보를
        // UserDetails 라는 객체를 통해서만 이해함.. (아이디, 비번, 보유권한..)
        Member member = memberRepository.findByHomepageId(homepageId).orElseThrow(() -> new MemberException(MemberErrorCode.MEMBER_NOT_FOUND));

        return new MemberUserDetails(member);
    }
}

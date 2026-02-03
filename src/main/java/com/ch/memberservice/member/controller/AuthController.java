package com.ch.memberservice.member.controller;

import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/auth")
// @Service같은 걸로 등록되어 있어야 RequiredArgsContructor가 작동한다.
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;

    // 회원 임시 등록 (비번을 암호화하여 임시로 등록해보기)
    // 우회해서 등록하려면 Filter를 거치지만 예외로 허용시켜서(requestMatchers) 바로 AuthController로 가게 만들고
    // 스프링 시큐리티에서 사용하는 MemberDetailService가 아닌 우리만의 service로 Manager에 접근해야 한다.
    @PostMapping("/temp")
    public ResponseEntity<?> tempRegist(MemberRequest memberRequest) {

        log.debug("homepageId is {}", memberRequest.getHomepageId());
        log.debug("password is {}", memberRequest.getPassword());
        log.debug("name is {}", memberRequest.getName());

        return ResponseEntity.ok(memberService.regist(memberRequest));
    }
}

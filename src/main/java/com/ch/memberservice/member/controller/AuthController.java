package com.ch.memberservice.member.controller;

import com.ch.memberservice.member.dto.MemberRequest;
import com.ch.memberservice.member.dto.MemberResponse;
import com.ch.memberservice.member.entity.MemberUserDetails;
import com.ch.memberservice.member.repository.MemberRepository;
import com.ch.memberservice.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.AuthenticationException;

@Slf4j
@RestController
@RequestMapping("/api/auth")
// @Service같은 걸로 등록되어 있어야 RequiredArgsContructor가 작동한다.
@RequiredArgsConstructor
public class AuthController {

    private final MemberService memberService;
    private final AuthenticationManager authenticationManager;

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

    /*-----------------------------------------------------------------------------------------
    로그인 요청 처리(스프링 필터체인의 요청을 받는 UsernamePasswordAuthenticationFilter를 거치지 않고
    직접 로그인 요청을 받는다. but AuthenticationManager에게 직접 일을 시켜보자)
    ------------------------------------------------------------------------------------------*/
    @PostMapping("/login")
    public ResponseEntity<?> login(MemberRequest memberRequest) {

        log.debug("로그인 요청 시 homepageId is {}", memberRequest.getHomepageId());
        log.debug("로그인 요청 시 password is {}", memberRequest.getPassword());

        // AuthenticationManaer 호출

        // authenticate(authentication) throws AuthenticationException;
        // Authentication Token을 구현한 구현체 - UsernamePasswordAuthenticationToken(Object principal, Object credentials)
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(memberRequest.getHomepageId(), memberRequest.getPassword()));
        // MemberUserDetails에는 password도 들어있으므로
        MemberUserDetails userDetails = (MemberUserDetails)auth.getPrincipal();

        // 로그인 성공하자마이니 많은 정보를 주지 않겠다. 마이페이지도 아니니까 null userDetails.getName()
        return ResponseEntity.ok(new MemberResponse(userDetails.getUsername(), null));
    }

    @ExceptionHandler(AuthenticationException.class)
    public String handle(AuthenticationException e) {
        log.debug("인증 실패했네요 ㅜㅜ");

        return e.getMessage();
    }
}

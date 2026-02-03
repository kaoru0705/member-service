package com.ch.memberservice.member.security;

import com.ch.memberservice.member.entity.MemberUserDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

// 회원이 인증된 후, UsernamePasswordAuthenticationFilter에 의해 성공 시 호출되는 핸들러
// 개발자는 로그인 성공 메시지 처리..
@Slf4j
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler{

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        MemberUserDetails memberUserDetails = (MemberUserDetails)authentication.getPrincipal();
        log.debug("성공 후 유저명 알아 맞추기 {}", memberUserDetails.getUsername());

        response.getWriter().write(memberUserDetails.getUsername() + "님 로그인 성공");
    }
}
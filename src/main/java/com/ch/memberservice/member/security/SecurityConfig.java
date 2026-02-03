package com.ch.memberservice.member.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, LoginSuccessHandler loginSuccessHandler) throws Exception {

        httpSecurity.csrf(csrf -> csrf.disable());
        httpSecurity.authorizeHttpRequests(auth -> auth
                // 어떤 preflight가 되든 다 허용
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/login").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
        );

        // 기본 폼로그인은 username, password를 사용한다. 우리는 homepageId, password를 사용하니 바꿔야 한다.
        // 폼로그인에 대한 설정
        httpSecurity.formLogin(form -> form
                .usernameParameter("homepageId")
                .passwordParameter("password")
                // component로 등록된 LoginSuccessHandler는 Bean에 등록해서 사용할 필요가 없다. ComponentScan
                .successHandler(loginSuccessHandler)
        );

        return httpSecurity.build();
    }


}

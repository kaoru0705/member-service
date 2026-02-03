package com.ch.memberservice.member.security;

import com.ch.memberservice.member.jwt.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    @Value("${app.frontend-url}")
    private String frontendUrl;

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        // CORS 정책을 담는 설정(허용할 출처/메서드(GET, POST...)/헤더 등) 객체
        CorsConfiguration config = new CorsConfiguration();
        // java 9이후부터 추가됐다. java.util.List.of() 상수 값, 고정된 리스트 정의 시 사용(완전 불변 (추가/삭제/수정 모두 불가)) Arrays.asList()와 다르다..
        config.setAllowedOrigins(List.of(frontendUrl)); // 금지사항!!! * 패턴금지 정확히 적어야 됨
        // Cross Origin 때문에 OPTIONS는 크롬브라우저가 로그인 패스 요청을 날리기 앞서서 preflight(시험 비행)로 허용할지 실험
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));     // header는 * 패턴 가능 혹시 보안을 더 강화할 일이 있다면, 헤더를 지정하는 게 좋다.
        // 로그인 성공 시 세션 쿠키에서 웹브라우저가 요청을 할 때 톰캣이 session Id를 줘야 함 true로 설정
        config.setAllowCredentials(false);   // 만일 true로 주지 않으면, 브라우저가 쿠키를 보내지 않거나 응답을 막음
        config.setMaxAge(3600L);    // 3600 초 동안 동일 조건이라면 preflight를 매번 하지 않음

        // 허용할 URI 패턴 우리의 경우 /api/**
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**",  config);

        return source;
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

        // JWT를 사용하기 때문에 더 이상, 세션을 만들지 않겠다.
        httpSecurity.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // JWT 필터 등록
        httpSecurity.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }


}

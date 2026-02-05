package com.ch.memberservice.member.repository;

import com.ch.memberservice.member.entity.Provider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ProviderRepository extends JpaRepository<Provider, Integer> {
    /* provider 테이블에서 공급자명으로 Provider를 찾기 위한 메서드 추가 */
    // JPA는 모든 컬럼에 대한 메서들르 제공하지 않는 대신, 단, JPA 내부적으로 정해놓은 규칙대로 메서드를 정의해야 동작함
    Optional<Provider> findByProviderName(String proividerName);   // Security에서는 공급자를 registrationId로 넘겨준다.
    // 그 registration은 yaml에 registration
}
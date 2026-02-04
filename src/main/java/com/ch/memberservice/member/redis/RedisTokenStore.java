package com.ch.memberservice.member.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

@RequiredArgsConstructor
@Component
public class RedisTokenStore {
    /*------------------------------------------------------------
    키 설계 (key-value) SET name "zino"
    rt:{memberId}:{jti}
    rt(refresh token), jt(jwt의 고유값(UUID))
    보안상 refresh토큰을 원본으로 redis value에 넣지 않는다. - redis 해킹당하면 답이 없다.
    따라서 refreshtoken의 가상값(hash시킨 값)을 value로 넣음
    RefreshToken 자체에는 로그인을 했는지 안 했는지 판단해야 한다.

    회원 번호 23번에 jti를 비교해서 갖고 있다면 로그인한 것으로 판단
    rt:current(현재 사용중인지 아닌지를 나타내는 키워드):{memberId} {jit} ex) rt:current:23 jti(UUID)
    로그인하면 멤버아이디를 통해 current key  값을 알 수 있고 그 value가 존재하지 않는다면 위에 rt:{memberId}:{jti} 이걸 제거

    refrehstoken 원문을 클라이언트에게 쿠키로 주지만 HttpOnly 옵션을 주니 JS에서 조작할 수 없다.
     ------------------------------------------------------------*/

    private final StringRedisTemplate redisTemplate;  // CRUD 전담 객체


    /*------------------------------------------------------------
    Refresh Token 저장
     ------------------------------------------------------------*/
    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void saveRefreshToken(Long memberId, String jti,  String refreshToken, long ttl) {
        // refresh token을 redis에 그냥 원문으로 넣으면, 보안상 위험하므로 암호화 시켜서 넣자
        String hashedRefreshToken = sha256(refreshToken);

        // key = rt:{memberId}:{jti}, value = hashedRefreshToken 리프레시 토큰 저장, milliSeconds -> Seconds
        redisTemplate.opsForValue().set("rt:" + memberId + ":" + jti, hashedRefreshToken, Duration.ofSeconds(ttl));

        // rt:current:{memberId} 리프레시 토큰의 현재 상태 정보 저장
        redisTemplate.opsForValue().set("rt:current:" + memberId, jti, Duration.ofSeconds(ttl));

    }

    /*------------------------------------------------------------
    Refresh Token 조회 (현재 유효한 refresh token 조회)
    Refresh Token의 존재를 조회하려면 먼저 rt:current:{memberId}를 통해 현재 사용되고 있는 JTI 가져와서,
    이 JTI를 갖는 토큰을 찾아야 함. 없으면 로그아웃 혹은 로그인한 적이 없거나 폐기 등.. 유효하지 않은 상태라고 간주..
    rt:current:{memberId}
     ------------------------------------------------------------*/
    public String getCurrentRefreshJti(Long memberId) {
        return redisTemplate.opsForValue().get("rt:current:" + memberId);   // UUID인 JTI가 반환
    }

    /*------------------------------------------------------------
    유효한 토큰 존재 여부 판단
    이 메서드는 사용자가 Refresh Token을 지참하여 서버로 전송했을 때 호출될 메서드..
    내가 이미 알고 있던 파라미터들과 비교
     ------------------------------------------------------------*/
    public boolean matchesRefreshToken(Long memberId, String jti, String refreshToken) {
        String currentJti = getCurrentRefreshJti(memberId);
        
        // 현재 상태를 표현하는 상태값이 존재하지 않거나, 혹은 일치하는 토큰의 jti가 없을 경우
        if(currentJti == null || !currentJti.equals(jti)) {
            return false;
        }

        // 서버에 저장된 리프레시 토큰 가져오기
        String savedHash = redisTemplate.opsForValue().get("rt:" + memberId + ":" + jti);
        if(savedHash == null) return false;

        return savedHash.equals(sha256(refreshToken));
    }

    /*------------------------------------------------------------
    Refresh Token 폐기(회전 = rotation = 재발급, 로그아웃)
    grant <-> revoke
    DEL rt:{memberId}:{jti}
    DEL rt:current:{memberId}
     ------------------------------------------------------------*/
    public void revokeRefreshToken(Long memberId, String jti) {
        redisTemplate.delete("rt" + memberId + ":" + jti);  // refresh token 삭제
        redisTemplate.delete("rt:current" + memberId);      // refresh token 상태값 삭제
    }

    /*------------------------------------------------------------
    전부 폐기(강제 로그아웃)
     ------------------------------------------------------------*/
    public void revokeAllByUser(Long memberId) {
        String jti = getCurrentRefreshJti(memberId);

        if(jti != null) {
            revokeRefreshToken(memberId, jti);
        } else {
            redisTemplate.delete("rt:current:" + memberId);
        }
    }

    /*------------------------------------------------------------
    블랙리스트 등록
    로그아웃을 안 한 상태에서 해커가 액세스 토큰을 털었다면?
    서버가 이상한 움직임을 감지하고 토큰을 발급은 했으나 사용하지 못하게 만들어야 한다. (삭제 이외에 방법)
    SET bl:at:{accessJti} 1 EX 200
     ------------------------------------------------------------*/
    public void blackListAccessToken(String accessJti, long ttl) {
        if(ttl <= 0) return;
        redisTemplate.opsForValue().set("bl:at:" + accessJti, "1", Duration.ofSeconds(ttl));
    }

    /*------------------------------------------------------------
    블랙리스트 확인
    SETY bl:at{jti} 1 EX 60
     ------------------------------------------------------------*/
    public boolean isAccessTokenBlacklisted(String accessJti) {
        Boolean exists = redisTemplate.hasKey("bl:at:" + accessJti);

        return (exists != null) && exists;
    }
}
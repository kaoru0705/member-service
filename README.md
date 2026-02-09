# JWT AccessToken과 RefreshToken을 사용하는 로그인
1. filterchain을 거치기 전 JwtAuthFilter에서 AccessToken이 존재하고 유효한지, redis를 통해 블랙리스트에는 안 들어갔는지를 확인한다.
2. 토큰이 존재하지 않는다면 필터로 가지만 permitALl로 바로 Controller에서 AuthenticationManager를 우회한다.
3. 아이디 비번이 유효할 경우 accessToken과 refreshToken을 발급한다. 또한 refreshToken은 redis에 저장된다.
4. 로그아웃을 할 경우, 블랙리스트에 accessToken을 집어 넣고, refreshToken은 redis에서 제거한다.

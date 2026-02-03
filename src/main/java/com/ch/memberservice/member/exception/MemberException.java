package com.ch.memberservice.member.exception;

import lombok.Getter;

//개발자가 예외처리를 하지 않아도 컴파일이 가능한 예외는 RuntimeException 이라 함
@Getter
public class MemberException  extends RuntimeException{
    //미리 만들어놓은 예외 코드 객체 사용하기
    private final MemberErrorCode errorCode;//에러 메시지 뿐만 아니라, 에러 코드도 이미 포함

    public MemberException(MemberErrorCode errorCode){
        super(errorCode.getMessage()); // 부모 RuntimeException의 생성자 매개변수로 에러 메시지 전달
                                                    // 부모의 생성자는 물려받지 못하므로, 부모의 생성자 호출을 통해서 전달
        this.errorCode = errorCode;
    }
}

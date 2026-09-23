package org.hooni.gateway.common.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 검증된 Access Token에서 추출한 최소 사용자 정보다.
 * 회원 상태 DTO가 아니며 현재 Gateway 요청의 인증 객체를 만드는 데만 사용한다.
 */
@Getter
@AllArgsConstructor
public class LoginStatus {
    private final String userCode;
    private final String name;
    private final String role;

    public static LoginStatus getSuccess(String userCode, String name, String role) {
        return new LoginStatus(userCode, name, role);
    }
}

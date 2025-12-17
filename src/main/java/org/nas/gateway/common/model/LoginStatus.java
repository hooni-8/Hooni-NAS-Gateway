package org.nas.gateway.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.nas.gateway.common.code.StatusCode;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginStatus {

    private boolean status = false;
    private String userCode;
    private String name;
    private String role;

    private String code;
    private String message;

    public static LoginStatus getSuccess(String userCode, String name, String role) {
        return LoginStatus.builder()
                .code(StatusCode.SUCCESS.getCode())
                .message(StatusCode.SUCCESS.getMessage())
                .status(true)
                .userCode(userCode)
                .name(name)
                .role(role)
                .build();
    }

    public static LoginStatus getError() {
        return LoginStatus.builder()
                .code(StatusCode.ERROR.getCode())
                .message(StatusCode.ERROR.getMessage())
                .status(false)
                .build();
    }

}

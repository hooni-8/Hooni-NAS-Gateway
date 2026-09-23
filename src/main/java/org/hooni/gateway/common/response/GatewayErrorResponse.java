package org.hooni.gateway.common.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.hooni.gateway.common.code.StatusCode;

/** Gateway 자체에서 발생한 인증·인가·라우팅 오류의 공통 응답 형식이다. */
@Getter
@AllArgsConstructor
public class GatewayErrorResponse {

    private final String code;
    private final String message;
    private final Object data;

    public static GatewayErrorResponse of(StatusCode statusCode) {
        return new GatewayErrorResponse(statusCode.getCode(), statusCode.getMessage(), null);
    }
}

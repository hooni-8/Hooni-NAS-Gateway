package org.nas.gateway.common.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.nas.gateway.common.code.StatusCode;

@Getter
@AllArgsConstructor
public class GatewayErrorResponse {

    private final String code;
    private final String message;
    private final Object data;

    public static GatewayErrorResponse of(String message) {
        return new GatewayErrorResponse(StatusCode.ERROR.getCode(), message, null);
    }
}

package org.hooni.gateway.common.code;

import lombok.Getter;

/** Gateway가 직접 생성하는 공통 오류 응답 코드다. */
@Getter
public enum StatusCode {
    BAD_REQUEST("GATEWAY_400", "BAD_REQUEST"),
    UNAUTHORIZED("GATEWAY_401", "UNAUTHORIZED"),
    FORBIDDEN("GATEWAY_403", "FORBIDDEN"),
    INVALID_ORIGIN("GATEWAY_403_ORIGIN", "INVALID_ORIGIN"),
    NOT_FOUND("GATEWAY_404", "NOT_FOUND"),
    METHOD_NOT_ALLOWED("GATEWAY_405", "METHOD_NOT_ALLOWED"),
    PAYLOAD_TOO_LARGE("GATEWAY_413", "PAYLOAD_TOO_LARGE"),
    TOO_MANY_REQUESTS("GATEWAY_429", "TOO_MANY_REQUESTS"),
    BAD_GATEWAY("GATEWAY_502", "BAD_GATEWAY"),
    GATEWAY_TIMEOUT("GATEWAY_504", "GATEWAY_TIMEOUT"),
    INTERNAL_SERVER_ERROR("GATEWAY_500", "INTERNAL_SERVER_ERROR"),
    ERROR("GATEWAY_9999", "ERROR");


    private final String code;

    private final String message;

    StatusCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public static StatusCode fromHttpStatus(int status) {
        return switch (status) {
            case 400 -> BAD_REQUEST;
            case 401 -> UNAUTHORIZED;
            case 403 -> FORBIDDEN;
            case 404 -> NOT_FOUND;
            case 405 -> METHOD_NOT_ALLOWED;
            case 413 -> PAYLOAD_TOO_LARGE;
            case 429 -> TOO_MANY_REQUESTS;
            case 502 -> BAD_GATEWAY;
            case 504 -> GATEWAY_TIMEOUT;
            case 500 -> INTERNAL_SERVER_ERROR;
            default -> ERROR;
        };
    }
}

package org.hooni.gateway.exception;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeoutException;


/**
 * Gateway 처리 중 발생한 예외에서 외부 공개용 HTTP 상태와 안전한 메시지만 추출한다.
 * 연결 실패는 502, timeout은 504로 구분하고 내부 예외 정보는 응답에서 제거한다.
 */
public class GlobalErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request, ErrorAttributeOptions options) {
        Map<String, Object> map = super.getErrorAttributes(request, options);

        Throwable error = this.getError(request);
        MergedAnnotation<ResponseStatus> responseStatusAnnotation = MergedAnnotations
                .from(error.getClass(), MergedAnnotations.SearchStrategy.TYPE_HIERARCHY).get(ResponseStatus.class);
        HttpStatusCode httpStatusCode = findHttpStatus(error, responseStatusAnnotation);
        HttpStatus httpStatus = HttpStatus.resolve(httpStatusCode.value());

        // 예외 클래스명·내부 메시지·스택 트레이스는 외부 응답으로 내보내지 않는다.
        map.remove("exception");
        map.remove("trace");
        map.put("status", httpStatusCode.value());
        map.put("error", httpStatus != null ? httpStatus.getReasonPhrase() : "Error");
        map.put(
                "message",
                httpStatusCode.value() == HttpStatus.INTERNAL_SERVER_ERROR.value()
                        ? "Internal server error"
                        : (httpStatus != null ? httpStatus.getReasonPhrase() : "Request failed")
        );

        return map;
    }

    private HttpStatusCode findHttpStatus(Throwable error, MergedAnnotation<ResponseStatus> responseStatusAnnotation) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof ResponseStatusException responseStatusException) {
                return responseStatusException.getStatusCode();
            }
            if (isTimeout(current)) {
                return HttpStatus.GATEWAY_TIMEOUT;
            }
            if (isBadGateway(current)) {
                return HttpStatus.BAD_GATEWAY;
            }
            if (current.getCause() == current) {
                break;
            }
            current = current.getCause();
        }
        return responseStatusAnnotation.getValue("code", HttpStatus.class).orElse(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private boolean isTimeout(Throwable error) {
        String simpleName = error.getClass().getSimpleName();
        return error instanceof TimeoutException
                || error instanceof SocketTimeoutException
                || "ReadTimeoutException".equals(simpleName)
                || "ConnectTimeoutException".equals(simpleName);
    }

    private boolean isBadGateway(Throwable error) {
        return error instanceof ConnectException
                || "PrematureCloseException".equals(error.getClass().getSimpleName());
    }
}

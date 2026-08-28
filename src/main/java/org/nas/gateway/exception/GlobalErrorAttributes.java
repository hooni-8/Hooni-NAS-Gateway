package org.nas.gateway.exception;

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
                httpStatusCode.is5xxServerError()
                        ? "Internal server error"
                        : (httpStatus != null ? httpStatus.getReasonPhrase() : "Request failed")
        );

        return map;
    }

    private HttpStatusCode findHttpStatus(Throwable error, MergedAnnotation<ResponseStatus> responseStatusAnnotation) {
        if (error instanceof ResponseStatusException) {
            return ((ResponseStatusException) error).getStatusCode();
        }
        return responseStatusAnnotation.getValue("code", HttpStatus.class).orElse(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

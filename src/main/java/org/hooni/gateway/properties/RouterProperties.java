package org.hooni.gateway.properties;

import lombok.Getter;
import lombok.Setter;

/** 개별 라우트의 대상 주소와 경로 제거·치환·prefix 규칙을 표현한다. */
@Getter
@Setter
public class RouterProperties extends CommonUrlProperties {
    private String prefix;
    private String rewrite;
    private boolean removeContext = false;
    /** true인 라우트에만 원본 Cookie 헤더를 전달한다. 기본값 false는 일반 API의 인증 쿠키 노출을 막는다. */
    private boolean forwardCookies = false;

    public void setPrefix(String prefix) {
        this.prefix = normalizePath(prefix);
    }

    public void setRewrite(String rewrite) {
        this.rewrite = normalizePath(rewrite);
    }

    public String getRoutedUrl() {
        if (removeContext) {
            return "";
        }
        String destination = rewrite == null || rewrite.isBlank() ? context : rewrite;
        return (prefix == null ? "" : prefix) + destination;
    }

    public void validateRoute(String routeId) {
        validate();
        if (context == null || context.isBlank()) {
            throw new IllegalStateException("Route context must not be blank: " + routeId);
        }
        if (removeContext && ((rewrite != null && !rewrite.isBlank())
                || (prefix != null && !prefix.isBlank()))) {
            throw new IllegalStateException(
                    "remove-context cannot be combined with rewrite or prefix: " + routeId
            );
        }
    }
}

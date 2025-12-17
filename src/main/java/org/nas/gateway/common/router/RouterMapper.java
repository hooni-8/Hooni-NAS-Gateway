package org.nas.gateway.common.router;

import lombok.Data;
import org.nas.gateway.properties.RouterProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@Data
@ConfigurationProperties(prefix = "routers")
public class RouterMapper {

    private Map<String, RouterProperties> defaults;

    public Map<String, RouterProperties> list() {
        return this.defaults;
    }
}

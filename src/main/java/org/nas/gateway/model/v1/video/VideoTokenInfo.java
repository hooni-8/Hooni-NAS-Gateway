package org.nas.gateway.model.v1.video;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VideoTokenInfo {

    private String userCode;
    private String fileId;
    private long expiredAt;
}
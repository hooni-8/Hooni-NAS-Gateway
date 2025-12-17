package org.nas.gateway.controller.v1;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/gateway")
public class GatewayRestController {

//    @Autowired
//    JwtTokenProvider jwtTokenProvider;
//
//    @GetMapping("/session")
//    public Mono<LoginStatus> session (@Parameter(hidden = true) @AuthenticationPrincipal Authentication authentication) {
//        LoginStatus loginInfo = new LoginStatus();
//
//        return Mono.just(loginInfo);
//    }
}

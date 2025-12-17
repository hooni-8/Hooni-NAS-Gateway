package org.nas.gateway.repository.auth;

import org.nas.gateway.entity.user.UserDetail;
import org.nas.gateway.repository.GatewayReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthRepository extends GatewayReactiveCrudRepository<UserDetail, Long> {

    Mono<UserDetail> findByUserId(String userId);

    Mono<UserDetail> findByUserCode(String userCode);

    Mono<Boolean> existsByUserId(String userId);
}

package org.hooni.gateway;

/** Gateway와 내부 API 사이에서 사용하는 신뢰 헤더 이름을 정의한다. */
public final class GatewayConsts {
	public static final String X_AUTHORITY_HEADER = "x-authority";
	public static final String X_CLIENT_IP_HEADER = "X-Client-IP";

	private GatewayConsts() {
	}
}

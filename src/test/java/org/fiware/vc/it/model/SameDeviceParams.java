package org.fiware.vc.it.model;

import lombok.Data;

@Data
public class SameDeviceParams {

	private String responseType;
	private String responseMode;
	private String clientId;
	private String redirectUri;
	private String state;
	private String nonce;
	private String scope;
}

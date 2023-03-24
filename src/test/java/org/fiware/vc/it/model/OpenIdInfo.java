package org.fiware.vc.it.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class OpenIdInfo {

	@JsonProperty("token_endpoint")
	private String tokenEndpoint;
	@JsonProperty("credential_endpoint")
	private String credentialEndpoint;
}

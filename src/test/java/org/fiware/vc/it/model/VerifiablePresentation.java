package org.fiware.vc.it.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerifiablePresentation {

	@JsonProperty("@context")
	private Set<String> context = Set.of("https://www.w3.org/2018/credentials/v1");
	private Set<String> type =  Set.of("VerifiablePresentation");
	// needs to be ordered
	private List<Object> verifiableCredential = new ArrayList<>();
	private String id;
	private String holder;
	private Object proof;
}

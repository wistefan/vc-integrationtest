package org.fiware.vc.it.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PresentationSubmission {

	private String id;
	@JsonProperty("definition_id")
	private String definitionId;
	@JsonProperty("descriptor_map")
	private Map<String, Object> descriptorMap;
}

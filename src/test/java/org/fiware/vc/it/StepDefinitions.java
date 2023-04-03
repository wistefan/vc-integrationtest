package org.fiware.vc.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.fiware.vc.it.model.HelperToken;
import org.fiware.vc.it.model.TokenResponse;
import org.fiware.vc.it.model.UserEnvironment;
import org.fiware.vc.it.model.ishare.DelegationEvidence;
import org.fiware.vc.it.model.ishare.Policy;
import org.fiware.vc.it.model.ishare.PolicyCreate;
import org.fiware.vc.it.model.ishare.PolicyResource;
import org.fiware.vc.it.model.ishare.PolicyRule;
import org.fiware.vc.it.model.ishare.PolicySet;
import org.fiware.vc.it.model.ishare.PolicyTarget;
import org.fiware.vc.it.model.ishare.Target;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.idm.ClientRepresentation;

import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.fiware.vc.it.TestUtils.getFormDataAsString;

public abstract class StepDefinitions {

	protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	protected static final HttpClient HTTP_CLIENT = HttpClient
			.newBuilder()
			// we dont follow the redirect directly, since we are not a real wallet
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	public UserEnvironment userEnvironment;

	protected PolicyCreate getIssuerPolicy(List<String> allowedRoles) {
		DelegationEvidence delegationEvidence = new DelegationEvidence();
		delegationEvidence.notBefore = Instant.now().getEpochSecond();
		// very short run times will allow repeated test runs
		delegationEvidence.notOnOrAfter = Instant.now().plus(Duration.of(10, ChronoUnit.SECONDS)).getEpochSecond();
		delegationEvidence.policyIssuer = PacketDeliveryEnvironment.PACKET_DELIVERY_EORI;
		Target target = new Target();
		target.accessSubject = HappyPetsEnvironment.HAPPYPETS_DID;
		delegationEvidence.target = target;

		PolicyResource policyResource = new PolicyResource();
		policyResource.attributes = allowedRoles;
		policyResource.identifiers = List.of("*");
		policyResource.type = "PacketDeliveryService";

		PolicyTarget policyTarget = new PolicyTarget();
		policyTarget.resource = policyResource;
		policyTarget.actions = List.of("ISSUE");

		Policy rolePolicy = new Policy();
		rolePolicy.rules = List.of(new PolicyRule());
		rolePolicy.target = policyTarget;

		PolicySet policySet = new PolicySet();
		policySet.policies = List.of(rolePolicy);

		delegationEvidence.policySets = List.of(policySet);

		PolicyCreate roleCreate = new PolicyCreate();
		roleCreate.delegationEvidence = delegationEvidence;
		return roleCreate;
	}

	protected PolicyCreate getRole(String roleName) {
		DelegationEvidence delegationEvidence = new DelegationEvidence();
		delegationEvidence.notBefore = Instant.now().getEpochSecond();
		delegationEvidence.notOnOrAfter = Instant.now().plus(Duration.of(10, ChronoUnit.MINUTES)).getEpochSecond();
		delegationEvidence.policyIssuer = PacketDeliveryEnvironment.PACKET_DELIVERY_EORI;
		Target target = new Target();
		target.accessSubject = roleName;
		delegationEvidence.target = target;

		PolicyResource policyResource = new PolicyResource();
		policyResource.attributes = List.of("*");
		policyResource.identifiers = List.of("*");
		policyResource.type = "DELIVERYORDER";

		PolicyTarget policyTarget = new PolicyTarget();
		policyTarget.resource = policyResource;
		policyTarget.actions = List.of("GET", "PUT", "PATCH");

		Policy rolePolicy = new Policy();
		rolePolicy.rules = List.of(new PolicyRule());
		rolePolicy.target = policyTarget;

		PolicySet policySet = new PolicySet();
		policySet.policies = List.of(rolePolicy);

		delegationEvidence.policySets = List.of(policySet);

		PolicyCreate roleCreate = new PolicyCreate();
		roleCreate.delegationEvidence = delegationEvidence;
		return roleCreate;
	}

	protected String getIShareJWT() throws Exception {
		HttpRequest helperRequest = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/token?clientId=%s&idpId=%s", TestEnvironment.TOKEN_HELPER_ADDRESS,
						PacketDeliveryEnvironment.PACKET_DELIVERY_EORI,
						PacketDeliveryEnvironment.PACKET_DELIVERY_EORI)))
				.GET()
				.build();
		HttpResponse<String> jwtResponse = HTTP_CLIENT.send(helperRequest, HttpResponse.BodyHandlers.ofString());
		HelperToken helperToken = OBJECT_MAPPER.readValue(jwtResponse.body(), HelperToken.class);
		Map<String, String> tokenRequestFormData = Map.of(
				"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer",
				"scope", "iShare",
				// we did not set a redirect_path, thus in samedevice we will end up where it began.
				"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				"client_id", PacketDeliveryEnvironment.PACKET_DELIVERY_EORI,
				"client_assertion", helperToken.getToken());
		HttpRequest tokenRequest = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/oauth2/token", TestEnvironment.KEYROCK_AR_ADDRESS)))
				.POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(tokenRequestFormData)))
				.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED)
				.build();
		HttpResponse<String> tokenResponse = HTTP_CLIENT.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
		return OBJECT_MAPPER.readValue(tokenResponse.body(), TokenResponse.class).getAccessToken();
	}

	protected String getHappyPetsIssuerBase() {
		return String.format("%s/realms/%s/verifiable-credential/%s",
				HappyPetsEnvironment.HAPPYPETS_ISSUER_ADDRESS,
				HappyPetsEnvironment.HAPPYPETS_ISSUER_REALM,
				HappyPetsEnvironment.HAPPYPETS_DID);
	}

	protected String getUserTokenForAccountsAtHappypets(String username, String password) {
		Keycloak adminAccess = KeycloakBuilder.builder()
				.username(HappyPetsEnvironment.HAPPTYPETS_ADMIN_USER)
				.password(HappyPetsEnvironment.HAPPTYPETS_ADMIN_PASSWORD)
				.realm("master")
				.grantType("password")
				.clientId("admin-cli")
				.serverUrl(HappyPetsEnvironment.HAPPYPETS_ISSUER_ADDRESS)
				.build();

		ClientRepresentation accountConsole = adminAccess
				.realm(HappyPetsEnvironment.HAPPYPETS_ISSUER_REALM)
				.clients()
				.findByClientId("account-console")
				.get(0);

		accountConsole.setDirectAccessGrantsEnabled(true);
		adminAccess.realm(HappyPetsEnvironment.HAPPYPETS_ISSUER_REALM).clients().get(accountConsole.getId())
				.update(accountConsole);

		TokenManager tokenManager = KeycloakBuilder.builder()
				.username(username)
				.password(password)
				.realm(HappyPetsEnvironment.HAPPYPETS_ISSUER_REALM)
				.grantType("password")
				.clientId("account-console")
				.serverUrl(HappyPetsEnvironment.HAPPYPETS_ISSUER_ADDRESS)
				.build()
				.tokenManager();
		return tokenManager.getAccessToken().getToken();
	}

}

package org.fiware.vc.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.fiware.keycloak.oidcvc.model.CredentialRequestVO;
import org.fiware.keycloak.oidcvc.model.CredentialResponseVO;
import org.fiware.keycloak.oidcvc.model.CredentialsOfferVO;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.fiware.vc.it.model.AuthResponseParams;
import org.fiware.vc.it.model.HelperToken;
import org.fiware.vc.it.model.StartSameDeviceParams;
import org.fiware.vc.it.model.OfferedCredential;
import org.fiware.vc.it.model.OpenIdInfo;
import org.fiware.vc.it.model.PresentationSubmission;
import org.fiware.vc.it.model.TokenResponse;
import org.fiware.vc.it.model.VerifiablePresentation;
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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class StepDefinitions {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final HttpClient HTTP_CLIENT = HttpClient
			.newBuilder()
			// we dont follow the redirect directly, since we are not a real wallet
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	// "World" object in the cucumber terminology. Allows to share state between the steps and therefore create continuous
	// flows. The map is instantiated in the cucumber-before method, thus individual to each scenario.
	public Map<String, Object> theWorld;

	@Before
	public void setupTheWorld() {
		theWorld = new HashMap<>();
	}

	@Given("The HappyPets issuer is ready to provide credentials.")
	public void happyPetsIsAvailable() throws Exception {
		HttpRequest wellKnownRequest = HttpRequest.newBuilder()
				.uri(URI.create(
						String.format("%s/.well-known/openid-credential-issuer",
								getHappyPetsIssuerBase())))
				.build();

		await().atMost(Duration.of(1, ChronoUnit.MINUTES))
				.until(() -> HTTP_CLIENT.send(wellKnownRequest, HttpResponse.BodyHandlers.ofString())
						.statusCode() == 200);
	}

	@When("The admin user requests a credentials offer from HappyPets.")
	public void happyPetsAdminGetCredentialsOffer() throws Exception {
		String adminJwt = getUserTokenForAccountsAtHappypets(HappyPetsEnvironment.HAPPTYPETS_GOLD_USER,
				HappyPetsEnvironment.HAPPTYPETS_GOLD_USER_PASSWORD);
		HttpRequest offerRequest = HttpRequest.newBuilder()
				.uri(URI.create(
						String.format("%s/credential-offer?type=PacketDeliveryService&format=ldp_vc",
								getHappyPetsIssuerBase())
				))
				.header("Authorization", String.format("Bearer %s", adminJwt)).build();
		HttpResponse<String> offerResponse = HTTP_CLIENT.send(offerRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, offerResponse.statusCode(), "An offer should have been presented.");
		CredentialsOfferVO credentialsOfferVO = OBJECT_MAPPER.readValue(offerResponse.body(), CredentialsOfferVO.class);
		theWorld.put("credentialsOffer", credentialsOfferVO);
	}

	@When("The users uses the offer to receive a credential.")
	public void userGetsCredential() throws Exception {
		CredentialsOfferVO offerVO = (CredentialsOfferVO) theWorld.get("credentialsOffer");
		assertNotNull(offerVO, "An offer should have already been received.");
		List<OfferedCredential> offeredCredentialList = offerVO.getCredentials()
				.stream()
				.map(o -> OBJECT_MAPPER.convertValue(o, OfferedCredential.class))
				.toList();
		// get well-known
		HttpRequest wellKnownRequest = HttpRequest.newBuilder()
				.uri(URI.create(
						String.format("%s/.well-known/openid-configuration",
								getHappyPetsIssuerBase())))
				.build();
		HttpResponse<String> response = HTTP_CLIENT.send(wellKnownRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, response.statusCode(), "A credentials issuer info should have been returned.");
		OpenIdInfo issuerInfo = OBJECT_MAPPER.readValue(response.body(),
				OpenIdInfo.class);
		theWorld.put("openIdInfo", issuerInfo);

		Map<String, String> tokenRequestFormData = Map.of("grant_type",
				"urn:ietf:params:oauth:grant-type:pre-authorized_code", "code",
				offerVO.getGrants().getPreAuthorizedCode());

		HttpRequest tokenRequest = HttpRequest.newBuilder()
				.uri(URI.create(issuerInfo.getTokenEndpoint()))
				.POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(tokenRequestFormData)))
				.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED)
				.build();
		HttpResponse<String> tokenResponse = HTTP_CLIENT.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, tokenResponse.statusCode(), "A valid token should have been returned.");
		TokenResponse tr = OBJECT_MAPPER.readValue(tokenResponse.body(), TokenResponse.class);
		CredentialRequestVO credentialRequestVO = new CredentialRequestVO();
		OfferedCredential offeredCredential = offeredCredentialList.get(0);
		credentialRequestVO.format(FormatVO.fromString(offeredCredential.getFormat()))
				.setTypes(List.of(offeredCredential.getType()));
		HttpRequest credentialRequest = HttpRequest.newBuilder()
				.uri(URI.create(issuerInfo.getCredentialEndpoint()))
				.POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(credentialRequestVO)))
				.header("Authorization", "Bearer " + tr.getAccessToken())
				.header("Content-Type", MediaType.APPLICATION_JSON)
				.build();
		HttpResponse<String> credentialResponse = HTTP_CLIENT.send(credentialRequest,
				HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, credentialResponse.statusCode(), "A credential should have been returned.");
		CredentialResponseVO credentialResponseVO = OBJECT_MAPPER.readValue(credentialResponse.body(),
				CredentialResponseVO.class);
		theWorld.put("credential", credentialResponseVO.getCredential());
	}

	@When("The user authenticates with the same-device flow.")
	public void authenticateViaSameDeviceFlow() throws Exception {
		String loginSession = UUID.randomUUID().toString();
		theWorld.put("loginSession", loginSession);

		// start the same-device flow
		HttpRequest startSameDevice = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/api/v1/samedevice?state=%s",
						PacketDeliveryEnvironment.PACKET_DELIVERY_VERIFIER_ADDRESS, loginSession)))
				.GET()
				.build();
		HttpResponse<String> sameDeviceResponse = HTTP_CLIENT.send(startSameDevice,
				HttpResponse.BodyHandlers.ofString());
		assertEquals(302, sameDeviceResponse.statusCode(), "We should receive a redirect.");
		String locationHeader = sameDeviceResponse.headers().firstValue("location").get();
		List<NameValuePair> params = URLEncodedUtils.parse(URI.create(locationHeader), Charset.forName("UTF-8"));
		StartSameDeviceParams startSameDeviceParams = new StartSameDeviceParams();
		params.forEach(p -> {
			switch (p.getName()) {
				case "response_type" -> startSameDeviceParams.setResponseType(p.getValue());
				case "response_mode" -> startSameDeviceParams.setResponseMode(p.getValue());
				case "client_id" -> startSameDeviceParams.setClientId(p.getValue());
				case "redirect_uri" -> startSameDeviceParams.setRedirectUri(p.getValue());
				case "state" -> startSameDeviceParams.setState(p.getValue());
				case "nonce" -> startSameDeviceParams.setNonce(p.getValue());
				case "scope" -> startSameDeviceParams.setScope(p.getValue());
				default -> log.warn("Received an unknown parameter: {}", p.getName());
			}
		});

		Object theCredential = theWorld.get("credential");

		VerifiablePresentation vp = new VerifiablePresentation();
		vp.setHolder(HappyPetsEnvironment.HAPPYPETS_GOLD_USER_DID);
		vp.getVerifiableCredential().add(theCredential);

		PresentationSubmission presentationSubmission = new PresentationSubmission();
		presentationSubmission.setId("Placeholder - not yet evaluated.");
		presentationSubmission.setDefinitionId("Example definition.");

		Base64.Encoder encoder = Base64.getUrlEncoder();

		URI authResponseUri = new URIBuilder(String.format("%s/api/v1/authentication_response",
				PacketDeliveryEnvironment.PACKET_DELIVERY_VERIFIER_ADDRESS))
				.addParameter("state", startSameDeviceParams.getState())
				.addParameter("vp_token", encoder.encodeToString(OBJECT_MAPPER.writeValueAsString(vp).getBytes()))
				.addParameter("presentation_submission",
						encoder.encodeToString(OBJECT_MAPPER.writeValueAsString(presentationSubmission).getBytes()))
				.build();

		// now send the vp. Var name looks weird, but makes sense in the context of the api
		HttpRequest authResponse = HttpRequest.newBuilder()
				.uri(authResponseUri)
				.GET()
				.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED)
				.build();
		HttpResponse<String> authResponseResponse = HTTP_CLIENT.send(authResponse,
				HttpResponse.BodyHandlers.ofString());
		assertEquals(302, authResponseResponse.statusCode(), "A same device response should be returned.");

		AuthResponseParams authResponseParams = new AuthResponseParams();
		String authLocationHeader = authResponseResponse.headers().firstValue("location").get();
		List<NameValuePair> authParams = URLEncodedUtils.parse(URI.create(authLocationHeader),
				Charset.forName("UTF-8"));
		authParams.forEach(p -> {
			switch (p.getName()) {
				case "code" -> authResponseParams.setCode(p.getValue());
				case "state" -> authResponseParams.setState(p.getValue());
				default -> log.warn("Received an unknown parameter: {}", p.getName());
			}
		});

		Map<String, String> tokenRequestFormData = Map.of(
				"grant_type", "authorization_code",
				"code", authResponseParams.getCode(),
				// we did not set a redirec_path, thus in samedevice we will end up where it began.
				"redirect_uri", PacketDeliveryEnvironment.PACKET_DELIVERY_VERIFIER_ADDRESS + "/");

		HttpRequest jwtRequest = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/token", PacketDeliveryEnvironment.PACKET_DELIVERY_VERIFIER_ADDRESS)))
				.POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(tokenRequestFormData)))
				.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED)
				.build();
		HttpResponse<String> tokenResponse = HTTP_CLIENT.send(jwtRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, tokenResponse.statusCode(), "A token should have been returned.");
		TokenResponse tr = OBJECT_MAPPER.readValue(tokenResponse.body(), TokenResponse.class);
		theWorld.put("jwt", tr.getAccessToken());
	}

	@Then("The user can access PacketDeliveries backend.")
	public void userAccessPdc() throws Exception {
		String jwt = (String) theWorld.get("jwt");
		HttpRequest orionRequest = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/ngsi-ld/v1/entities/urn:ngsi-ld:DELIVERYORDER:1",
						PacketDeliveryEnvironment.PACKET_DELIVERY_ORION_ADDRESS)))
				.GET()
				.header("Authorization", "Bearer " + jwt)
				.build();
		HttpResponse<String> orionResponse = HTTP_CLIENT.send(orionRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(404, orionResponse.statusCode(), "The request should be allowed.");
	}

	@When("The policies are properly setup.")
	public void setupPolicies() throws Exception {
		String token = getIShareJWT();

		HttpResponse<String> standardRoleResponse = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
				.POST(HttpRequest.BodyPublishers.ofString(
						OBJECT_MAPPER.writeValueAsString(getRole("STANDARD_CUSTOMER"))))
				.uri(URI.create(String.format("%s/ar/policy", TestEnvironment.KEYROCK_AR_ADDRESS)))
				.header("Content-Type", "application/json")
				.header("Authorization", String.format("Bearer %s", token))
				.version(HttpClient.Version.HTTP_1_1)
				.build(), HttpResponse.BodyHandlers.ofString());

		HttpResponse<String> goldRoleResponse = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
				.POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(getRole("GOLD_CUSTOMER"))))
				.uri(URI.create(String.format("%s/ar/policy", TestEnvironment.KEYROCK_AR_ADDRESS)))
				.header("Content-Type", "application/json")
				.header("Authorization", String.format("Bearer %s", token))
				.version(HttpClient.Version.HTTP_1_1)
				.build(), HttpResponse.BodyHandlers.ofString());

		HttpResponse<String> issuerResponse = HttpClient.newHttpClient().send(
				HttpRequest.newBuilder()
						.POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(
								getIssuerPolicy(List.of("STANDARD_CUSTOMER", "GOLD_CUSTOMER")))))
						.uri(URI.create(String.format("%s/ar/policy", TestEnvironment.KEYROCK_AR_ADDRESS)))
						.header("Content-Type", "application/json")
						.header("Authorization", String.format("Bearer %s", token))
						.version(HttpClient.Version.HTTP_1_1)
						.build(), HttpResponse.BodyHandlers.ofString());

		assertEquals(HttpStatus.SC_OK, standardRoleResponse.statusCode(), "The standard role should have been created.");
		assertEquals(HttpStatus.SC_OK, goldRoleResponse.statusCode(), "The gold role should have been created.");
		assertEquals(HttpStatus.SC_OK, issuerResponse.statusCode(), "The issuer policy should have been created.");

	}

	private PolicyCreate getIssuerPolicy(List<String> allowedRoles) {
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

	private PolicyCreate getRole(String roleName) {
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

	private String getIShareJWT() throws Exception {
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

	private String getHappyPetsIssuerBase() {
		return String.format("%s/realms/%s/verifiable-credential/%s",
				HappyPetsEnvironment.HAPPYPETS_ISSUER_ADDRESS,
				HappyPetsEnvironment.HAPPYPETS_ISSUER_REALM,
				HappyPetsEnvironment.HAPPYPETS_DID);
	}

	private String getUserTokenForAccountsAtHappypets(String username, String password) {
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

	private static String getFormDataAsString(Map<String, String> formData) {
		StringBuilder formBodyBuilder = new StringBuilder();
		for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
			if (formBodyBuilder.length() > 0) {
				formBodyBuilder.append("&");
			}
			formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
			formBodyBuilder.append("=");
			formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
		}
		return formBodyBuilder.toString();
	}

}
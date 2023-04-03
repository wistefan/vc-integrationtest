package org.fiware.vc.it.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.fiware.keycloak.oidcvc.model.CredentialRequestVO;
import org.fiware.keycloak.oidcvc.model.CredentialResponseVO;
import org.fiware.keycloak.oidcvc.model.CredentialsOfferVO;
import org.fiware.keycloak.oidcvc.model.FormatVO;
import org.fiware.vc.it.HappyPetsEnvironment;
import org.fiware.vc.it.PacketDeliveryEnvironment;
import org.fiware.vc.it.TestUtils;

import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class Wallet {

	// even thought its best practice to just use one ObjectMapper per JVM, we accept the performance impact for the tests
	// to improve readability and test isolation.
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final HttpClient HTTP_CLIENT = HttpClient
			.newBuilder()
			// we dont follow the redirect directly, since we are not a real wallet
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	private CredentialsOfferVO credentialsOffer;
	private OpenIdInfo issuerInfo;
	private Object credential;
	private String accessToken;

	public void getCredentialsOffer(String keycloakJwt, String connectionString) throws Exception {
		HttpRequest offerRequest = HttpRequest.newBuilder()
				.uri(URI.create(connectionString))
				.header("Authorization", String.format("Bearer %s", keycloakJwt)).build();
		HttpResponse<String> offerResponse = HTTP_CLIENT.send(offerRequest, HttpResponse.BodyHandlers.ofString());

		assertEquals(HttpStatus.SC_OK, offerResponse.statusCode(), "An offer should have been presented.");

		credentialsOffer = OBJECT_MAPPER.readValue(offerResponse.body(), CredentialsOfferVO.class);
	}

	public void getIssuerOpenIdConfiguration() throws Exception {
		String issuerAddress = credentialsOffer.getCredentialIssuer();

		// get well-known
		HttpRequest wellKnownRequest = HttpRequest.newBuilder()
				.uri(URI.create(
						String.format("%s/.well-known/openid-configuration",
								issuerAddress)))
				.build();
		HttpResponse<String> response = HTTP_CLIENT.send(wellKnownRequest, HttpResponse.BodyHandlers.ofString());

		assertEquals(HttpStatus.SC_OK, response.statusCode(), "A credentials issuer info should have been returned.");

		issuerInfo = OBJECT_MAPPER.readValue(response.body(),
				OpenIdInfo.class);
	}

	public void getTokenFromIssuer() throws Exception {
		Map<String, String> tokenRequestFormData = Map.of("grant_type",
				"urn:ietf:params:oauth:grant-type:pre-authorized_code", "code",
				credentialsOffer.getGrants().getPreAuthorizedCode());

		HttpRequest tokenRequest = HttpRequest.newBuilder()
				.uri(URI.create(issuerInfo.getTokenEndpoint()))
				.POST(HttpRequest.BodyPublishers.ofString(TestUtils.getFormDataAsString(tokenRequestFormData)))
				.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED)
				.build();
		HttpResponse<String> tokenResponse = HTTP_CLIENT.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, tokenResponse.statusCode(), "A valid token should have been returned.");
		TokenResponse tr = OBJECT_MAPPER.readValue(tokenResponse.body(), TokenResponse.class);

		accessToken = tr.getAccessToken();
	}

	public void getTheCredential() throws Exception {

		List<OfferedCredential> offeredCredentialList = credentialsOffer.getCredentials()
				.stream()
				.map(credentialObject -> OBJECT_MAPPER.convertValue(credentialObject, OfferedCredential.class))
				.toList();

		CredentialRequestVO credentialRequestVO = new CredentialRequestVO();
		OfferedCredential offeredCredential = offeredCredentialList.get(0);
		credentialRequestVO.format(FormatVO.fromString(offeredCredential.getFormat()))
				.setTypes(List.of(offeredCredential.getType()));

		HttpRequest credentialRequest = HttpRequest.newBuilder()
				.uri(URI.create(issuerInfo.getCredentialEndpoint()))
				.POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(credentialRequestVO)))
				.header("Authorization", "Bearer " + accessToken)
				.header("Content-Type", MediaType.APPLICATION_JSON)
				.build();
		HttpResponse<String> credentialResponse = HTTP_CLIENT.send(credentialRequest,
				HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, credentialResponse.statusCode(), "A credential should have been returned.");

		CredentialResponseVO credentialResponseVO = OBJECT_MAPPER.readValue(credentialResponse.body(),
				CredentialResponseVO.class);

		credential = credentialResponseVO.getCredential();
	}

	public AuthResponseParams answerAuthRequest(SameDeviceParams sameDeviceParams) throws Exception {

		VerifiablePresentation vp = new VerifiablePresentation();
		vp.setHolder(HappyPetsEnvironment.HAPPYPETS_GOLD_USER_DID);
		vp.getVerifiableCredential().add(credential);

		PresentationSubmission presentationSubmission = new PresentationSubmission();
		presentationSubmission.setId("Placeholder - not yet evaluated.");
		presentationSubmission.setDefinitionId("Example definition.");

		Base64.Encoder encoder = Base64.getUrlEncoder();

		URI authResponseUri = new URIBuilder(String.format("%s/api/v1/authentication_response",
				PacketDeliveryEnvironment.PACKET_DELIVERY_VERIFIER_ADDRESS))
				.addParameter("state", sameDeviceParams.getState())
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

		assertNotNull(authResponseParams.getCode(), "An authorization code should have been received.");
		assertNotNull(authResponseParams.getState(), "A state should have been received.");

		return authResponseParams;
	}

	public Optional<CredentialsOfferVO> getCredentialsOffer() {
		return Optional.ofNullable(credentialsOffer);
	}

	public Optional<OpenIdInfo> getIssuerInfo() {
		return Optional.ofNullable(issuerInfo);
	}

	public Optional<Object> getCredential() {
		return Optional.ofNullable(credential);
	}

	public Optional<String> getAccessToken() {
		return Optional.ofNullable(accessToken);
	}
}

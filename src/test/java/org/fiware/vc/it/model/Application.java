package org.fiware.vc.it.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.fiware.vc.it.TestUtils.getFormDataAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class Application {

	// even thought its best practice to just use one ObjectMapper per JVM, we accept the performance impact for the tests
	// to improve readability and test isolation.
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private static final HttpClient HTTP_CLIENT = HttpClient
			.newBuilder()
			// we dont follow the redirect directly, since we are not a real wallet
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	@Getter
	@Setter
	private ApplicationConfig applicationConfig;

	private String loginSession;
	private String jwt;

	public void initiateLogin() {
		loginSession = UUID.randomUUID().toString();
	}

	public SameDeviceParams startSameDeviceFlow() throws Exception {
		HttpRequest startSameDevice = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/api/v1/samedevice?state=%s",
						applicationConfig.verifierAddress(), loginSession)))
				.GET()
				.build();
		HttpResponse<String> sameDeviceResponse = HTTP_CLIENT.send(startSameDevice,
				HttpResponse.BodyHandlers.ofString());

		assertEquals(302, sameDeviceResponse.statusCode(), "We should receive a redirect.");

		String locationHeader = sameDeviceResponse.headers().firstValue("location").get();
		List<NameValuePair> params = URLEncodedUtils.parse(URI.create(locationHeader), Charset.forName("UTF-8"));
		SameDeviceParams sameDeviceParams = new SameDeviceParams();
		params.forEach(p -> {
			switch (p.getName()) {
				case "response_type" -> sameDeviceParams.setResponseType(p.getValue());
				case "response_mode" -> sameDeviceParams.setResponseMode(p.getValue());
				case "client_id" -> sameDeviceParams.setClientId(p.getValue());
				case "redirect_uri" -> sameDeviceParams.setRedirectUri(p.getValue());
				case "state" -> sameDeviceParams.setState(p.getValue());
				case "nonce" -> sameDeviceParams.setNonce(p.getValue());
				case "scope" -> sameDeviceParams.setScope(p.getValue());
				default -> log.warn("Received an unknown parameter: {}", p.getName());
			}
		});

		assertEquals("vp_token", sameDeviceParams.getResponseType(), "Currently, only vp_token is supported.");
		assertEquals("direct_post", sameDeviceParams.getResponseMode(), "Currently, only direct_post is supported.");
		assertEquals(applicationConfig.verifierDid(), sameDeviceParams.getClientId(),
				"The expected participant should have initiated the flow.");
		assertNotNull(sameDeviceParams.getRedirectUri(), "A redirect_uri should have been received.");
		assertNotNull(sameDeviceParams.getState(), "The verifier should have creadet a state.");

		return sameDeviceParams;
	}

	public void exchangeCodeForJWT(AuthResponseParams authResponseParams) throws Exception {
		Map<String, String> tokenRequestFormData = Map.of(

				"grant_type", "authorization_code",
				"code", authResponseParams.getCode(),
				// we did not set a redirect_path, thus in same device we will end up where it began.
				"redirect_uri", applicationConfig.applicationUrl() + "/");

		HttpRequest jwtRequest = HttpRequest.newBuilder()
				.uri(URI.create(
						String.format("%s%s", applicationConfig.verifierAddress(), applicationConfig.tokenPath())))
				.POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(tokenRequestFormData)))
				.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED)
				.build();
		HttpResponse<String> tokenResponse = HTTP_CLIENT.send(jwtRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(HttpStatus.SC_OK, tokenResponse.statusCode(), "A token should have been returned.");
		TokenResponse tr = OBJECT_MAPPER.readValue(tokenResponse.body(), TokenResponse.class);

		jwt = tr.getAccessToken();
	}

	public void accessBackend() throws Exception {

		HttpRequest orionRequest = HttpRequest.newBuilder()
				.uri(URI.create(String.format("%s/ngsi-ld/v1/entities/urn:ngsi-ld:DELIVERYORDER:1",
						applicationConfig.securedBackend())))
				.GET()
				.header("Authorization", "Bearer " + jwt)
				.build();
		HttpResponse<String> orionResponse = HTTP_CLIENT.send(orionRequest, HttpResponse.BodyHandlers.ofString());
		assertEquals(404, orionResponse.statusCode(), "The request should have been allowed.");
	}

	public Optional<String> getLoginSession() {
		return Optional.ofNullable(loginSession);
	}

	public Optional<String> getJwt() {
		return Optional.ofNullable(jwt);
	}

}

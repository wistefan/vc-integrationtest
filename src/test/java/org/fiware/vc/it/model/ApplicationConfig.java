package org.fiware.vc.it.model;

public record ApplicationConfig(String applicationUrl, String verifierDid, String verifierAddress, String tokenPath, String securedBackend) {

}

# VC-Integration Test

This repository contains a framework for writing Integration-Tests, integrating multiple components for 
authentication/authorization based on [VerifiableCredentials](https://www.w3.org/TR/vc-data-model/).

The components involved are:
* [Keycloak](https://www.keycloak.org/) with the [Keycloak-VC-Issuer](https://github.com/wistefan/keycloak-vc-issuer) to issue VerifiableCredentials 
* [VCVerifier](https://github.com/FIWARE/VCVerifier) to verify credentials and exchange them with [JWT](https://www.rfc-editor.org/rfc/rfc7519) via [SIOP-2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-cross-device-self-issued-op)/[OIDC4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#request_scope)
* [DSBA-PDP](https://github.com/FIWARE/dsba-pdp) acting as a Policy-Decision-Point(PDP) to make authorization decisions based on the JWT's
* [Kong](https://konghq.com/) with the [Kong-PEP-Plugin](https://github.com/FIWARE/kong-plugins-fiware/tree/main/kong-pep-plugin) acting as a Policy-Enforcement-Point(PEP), offering the APIs to the world and requesting decision for requests at the PDP.
* [Keyrock](https://github.com/ging/fiware-idm) as an [iShare](https://dev.ishare.eu/index.html) compliant AuthorizationRegistry, acting as the Policy-Administration-Point(PAP), providing the policies to the PDP.
* [WaltID SSIKit](https://github.com/walt-id/waltid-ssikit) as a downstream component, providing various functionalities around DIDs and VCs to Keycloak and VCVerifier
* [FIWARE iShare Satellite](https://github.com/FIWARE/ishare-satellite) to act as Trusted-Issuers-Registry(TIR) and iShare-TrustAnchor.
* [Orion-LD](https://github.com/FIWARE/context.Orion-LD) as [NGSI-LD](https://www.etsi.org/deliver/etsi_gs/CIM/001_099/009/01.06.01_60/gs_cim009v010601p.pdf) ContextBroker, to provide a backend-service.
* [iShare-JWT-Helper](https://github.com/wistefan/ishare-jwt-helper) as a convenience service for generating iShare-compliant tokens to be used with Keyrock.


## Local setup

In order to spin-up a local-environment, the maven-profile ```dev``` is provided. Its using the [kokuwaio/k3s-maven-plugin](https://github.com/kokuwaio/k3s-maven-plugin) 
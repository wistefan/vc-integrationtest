package org.fiware.vc.it;

public class HappyPetsEnvironment {

	public static String HAPPYPETS_DID = "did:key:z6MkigCEnopwujz8Ten2dzq91nvMjqbKQYcifuZhqBsEkH7g";
	public static String HAPPYPETS_EORI = "EU.EORI.HAPPYPETS";
	public static String HAPPTYPETS_ADMIN_USER = "admin";
	public static String HAPPTYPETS_ADMIN_PASSWORD = "admin";
	public static String HAPPTYPETS_STANDARD_USER = "standard-user";
	public static String HAPPTYPETS_STANDARD_USER_PASSWORD = "standard";
	public static String HAPPTYPETS_GOLD_USER = "gold-user";
	public static String HAPPTYPETS_GOLD_USER_PASSWORD = "password";
	// currently not verified, thus does not need to be a real one
	public static String HAPPYPETS_ADMIN_DID = "did:my:admin";
	public static String HAPPYPETS_GOLD_USER_DID = "did:user:gold";
	public static String HAPPYPETS_STANDARD_USER_DID = "did:user:standard";

	// the keycloak
	public static String HAPPYPETS_ISSUER_ADDRESS = "http://localhost:8080/";
	public static String HAPPYPETS_ISSUER_REALM = "fiware-server";

}

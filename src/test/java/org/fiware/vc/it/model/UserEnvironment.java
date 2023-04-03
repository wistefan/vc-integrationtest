package org.fiware.vc.it.model;

import lombok.Getter;

/**
 * Representation of a User's environment. This represents the components used by and end-user(either humand or machine) to
 * interact with the consumer and provider environments.
 */
@Getter
public class UserEnvironment {

	/**
	 * The wallet of the user. It will contain all
	 */
	private final Wallet wallet = new Wallet();
	private final Application application = new Application();
}

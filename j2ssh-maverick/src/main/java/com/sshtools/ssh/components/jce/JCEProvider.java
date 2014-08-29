/**
 * Copyright 2003-2014 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.ssh.components.jce;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Hashtable;

public class JCEProvider implements JCEAlgorithms {

	static Provider defaultProvider = null;
	static Hashtable<String, Provider> specficProviders = new Hashtable<String, Provider>();
	static String secureRandomAlgorithm = JCE_SHA1PRNG;

	static SecureRandom secureRandom;

	/**
	 * Initialize the default JCE provider used by the API.
	 * 
	 * @param provider
	 */
	public static void initializeDefaultProvider(Provider provider) {
		JCEProvider.defaultProvider = provider;
	}

	/**
	 * Initialize a provider for a specific algorithm.
	 * 
	 * @param jceAlgorithm
	 * @param provider
	 */
	public static void initializeProviderForAlgorithm(String jceAlgorithm,
			Provider provider) {
		specficProviders.put(jceAlgorithm, provider);
	}

	/**
	 * Get the algorithm used for secure random number generation.
	 * 
	 * @return String
	 */
	public static String getSecureRandomAlgorithm() {
		return secureRandomAlgorithm;
	}

	/**
	 * Set the algorithm used for secure random number generation.
	 * 
	 * @param secureRandomAlgorithm
	 */
	public static void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
		JCEProvider.secureRandomAlgorithm = secureRandomAlgorithm;
	}

	/**
	 * Get the provider for a specific algorithm.
	 * 
	 * @param jceAlgorithm
	 * @return Provider
	 */
	public static Provider getProviderForAlgorithm(String jceAlgorithm) {
		if (specficProviders.containsKey(jceAlgorithm)) {
			return (Provider) specficProviders.get(jceAlgorithm);
		}

		return defaultProvider;
	}

	/**
	 * Get the secure random implementation for the API.
	 * 
	 * @return SecureRandom
	 * @throws NoSuchAlgorithmException
	 */
	public static SecureRandom getSecureRandom()
			throws NoSuchAlgorithmException {

		if (secureRandom == null) {
			try {
				return secureRandom = JCEProvider
						.getProviderForAlgorithm(JCEProvider
								.getSecureRandomAlgorithm()) == null ? SecureRandom
						.getInstance(JCEProvider.getSecureRandomAlgorithm())
						: SecureRandom.getInstance(JCEProvider
								.getSecureRandomAlgorithm(), JCEProvider
								.getProviderForAlgorithm(JCEProvider
										.getSecureRandomAlgorithm()));
			} catch (NoSuchAlgorithmException e) {
				return secureRandom = SecureRandom.getInstance(JCEProvider
						.getSecureRandomAlgorithm());
			}
		}

		return secureRandom;
	}
}

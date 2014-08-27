package com.sshtools.ssh.components.jce;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Hashtable;

public class JCEProvider implements JCEAlgorithms {

	static Provider defaultProvider = null;
	static Hashtable specficProviders = new Hashtable();
	static String secureRandomAlgorithm = JCE_SHA1PRNG;

	static SecureRandom secureRandom;
	/**
	 * Initialize the default JCE provider used by the API. 
	 * @param provider
	 */
	public static void initializeDefaultProvider(Provider provider) {
		JCEProvider.defaultProvider = provider;
	}

	/**
	 * Initialize a provider for a specific algorithm.
	 * @param jceAlgorithm
	 * @param provider
	 */
	public static void initializeProviderForAlgorithm(String jceAlgorithm, Provider provider) {
		specficProviders.put(jceAlgorithm, provider);
	}

	/**
	 * Get the algorithm used for secure random number generation.
	 * @return String
	 */
	public static String getSecureRandomAlgorithm() {
		return secureRandomAlgorithm;
	}

	/**
	 * Set the algorithm used for secure random number generation.
	 * @param secureRandomAlgorithm
	 */
	public static void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
		JCEProvider.secureRandomAlgorithm = secureRandomAlgorithm;
	}

	/**
	 * Get the provider for a specific algorithm.
	 * @param jceAlgorithm
	 * @return Provider
	 */
	public static Provider getProviderForAlgorithm(String jceAlgorithm) {
		if(specficProviders.containsKey(jceAlgorithm)) {
			return (Provider) specficProviders.get(jceAlgorithm);
		}
		
		return defaultProvider;
	}	
	
	/**
	 * Get the secure random implementation for the API.
	 * @return SecureRandom
	 * @throws NoSuchAlgorithmException
	 */
	public static SecureRandom getSecureRandom() throws NoSuchAlgorithmException {

		if(secureRandom==null) {
			try {
				return secureRandom = JCEProvider.getProviderForAlgorithm(JCEProvider.getSecureRandomAlgorithm())==null ?
					SecureRandom.getInstance(JCEProvider.getSecureRandomAlgorithm()) :
						SecureRandom.getInstance(JCEProvider.getSecureRandomAlgorithm(),
								JCEProvider.getProviderForAlgorithm(JCEProvider.getSecureRandomAlgorithm()));
			} catch (NoSuchAlgorithmException e) {
				return secureRandom = SecureRandom.getInstance(JCEProvider.getSecureRandomAlgorithm());
			}
		}
		
		return secureRandom;
	}	
}

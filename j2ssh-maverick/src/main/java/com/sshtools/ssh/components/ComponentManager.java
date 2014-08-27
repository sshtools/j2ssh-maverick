package com.sshtools.ssh.components;

import java.math.BigInteger;

import com.sshtools.events.EventLog;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.jce.JCEComponentManager;

/**
 * <p>An abstract class that manages the components used by the SSH API. All 
 * algorithm implementations are obtained through a single provider. One implementation is provided
 * the {@link com.sshtools.ssh.components.jce.JCEComponentManager} that uses
 * the Java runtime JCE provider(s) algorithm implementations.</p>
 * 
 * @author Lee David Painter
 *
 */
public abstract class ComponentManager {

	private static boolean PerContextAlgorithmPreferences=false;
	private static boolean enableNoneCipher = false;
	private static boolean enableNoneMac = false;
	
	public static boolean isEnableNoneCipher() {
		return enableNoneCipher;
	}

	public static void setEnableNoneCipher(boolean enableNoneCipher) {
		ComponentManager.enableNoneCipher = enableNoneCipher;
	}
	
	public static boolean isEnableNoneMac() {
		return enableNoneMac;
	}

	public static void setEnableNoneMac(boolean enableNoneCipher) {
		ComponentManager.enableNoneMac = enableNoneCipher;
	}


	public static void setPerContextAlgorithmPreferences(boolean enable) {
		PerContextAlgorithmPreferences=enable;
	}
	
	public static boolean getPerContextAlgorithmPreferences() {
		return PerContextAlgorithmPreferences;
	}
	
	private static ComponentManager instance;

    ComponentFactory ssh2ciphersSC;
    ComponentFactory ssh2ciphersCS;
	ComponentFactory hmacsCS;
	ComponentFactory hmacsSC;
	ComponentFactory keyexchange;
	ComponentFactory publickeys;
	ComponentFactory digests;
	static Object lock = new Object();

	/**
	 * Get the installed component manager.
	 * Don't want to initialize this at class load time, so use a singleton instead.  Initialized on the first call to getInstance. 
	 * @return ComponentManager
	 */
	public static ComponentManager getInstance() {
		synchronized (ComponentManager.class) {
			if(instance==null) {
				instance = new JCEComponentManager();
			}
			return instance;		
		}
	}

	protected void init() throws SshException {
		
	    EventLog.LogEvent(this, "Initializing SSH2 server->client ciphers");
	    
		ssh2ciphersSC = new ComponentFactory(SshCipher.class);
	    initializeSsh2CipherFactory(ssh2ciphersSC);
    
	    if(enableNoneCipher) {
	    	ssh2ciphersSC.add("none", NoneCipher.class);
	    	EventLog.LogEvent(this, "   none will be a supported cipher");
	    }
	    
	    EventLog.LogEvent(this, "Initializing SSH2 client->server ciphers");
	    
	    ssh2ciphersCS = new ComponentFactory(SshCipher.class);
	    initializeSsh2CipherFactory(ssh2ciphersCS);

	    if(enableNoneCipher) {
	    	ssh2ciphersCS.add("none", NoneCipher.class);
	    	EventLog.LogEvent(this, "   none will be a supported cipher");
	    }
	    
	    EventLog.LogEvent(this, "Initializing SSH2 server->client HMACs");
	    
	    hmacsSC = new ComponentFactory(SshHmac.class);
	    initializeHmacFactory(hmacsSC);

	    if (enableNoneMac) {
			hmacsSC.add("none", NoneHmac.class);
			EventLog.LogEvent(this, "   none will be a supported hmac");
		}
	    
	    EventLog.LogEvent(this, "Initializing SSH2 client->server HMACs");
	    
	    hmacsCS = new ComponentFactory(SshHmac.class);
	    initializeHmacFactory(hmacsCS);
	    
	    if (enableNoneMac) {
			hmacsCS.add("none", NoneHmac.class);
			EventLog.LogEvent(this, "   none will be a supported hmac");
		}
	    
	    EventLog.LogEvent(this, "Initializing public keys");
	    
	    publickeys = new ComponentFactory(SshPublicKey.class);
		initializePublicKeyFactory(publickeys);

		EventLog.LogEvent(this, "Initializing digests");

	    digests = new ComponentFactory(SshPublicKey.class);
		initializeDigestFactory(digests);
		
		EventLog.LogEvent(this, "Initializing SSH2 key exchanges");
		
	    keyexchange = new ComponentFactory(SshKeyExchange.class);
	    initializeKeyExchangeFactory(keyexchange);

		EventLog.LogEvent(this, "Initializing Secure Random Number Generator");
		getRND().nextInt();
	}

	/**
	 * Initialize the SSH2 cipher factory. These ciphers are exclusively used by the SSH2
	 * implementation.
	 * @param ciphers
	 */
	protected abstract void initializeSsh2CipherFactory(ComponentFactory ciphers);

	/**
	 * Initialize the SSH2 HMAC factory. 
	 * @param hmacs
	 */
	protected abstract void initializeHmacFactory(ComponentFactory hmacs);

	/**
	 * Initialize the public key factory.
	 * @param publickeys
	 */
	protected abstract void initializePublicKeyFactory(ComponentFactory publickeys);

	/**
	 * Initialize the SSH2 key exchange factory.
	 * @param keyexchange
	 */
	protected abstract void initializeKeyExchangeFactory(ComponentFactory keyexchange);

	/**
	 * Initialize the digest factory. 
	 * @param digests
	 */
	protected abstract void initializeDigestFactory(ComponentFactory digests);

	/**
	 * Overide the installed component manager with an alternative implementation. 
	 * @param instance
	 */
	public static void setInstance(ComponentManager instance) {
		ComponentManager.instance = instance;
	}

	/**
	 * The supported SSH2 ciphers.
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedSsh2CiphersSC() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) ssh2ciphersSC.clone();
		}
		return ssh2ciphersSC;
	}
	
	/**
	 * The supported SSH2 ciphers.
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedSsh2CiphersCS() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) ssh2ciphersCS.clone();
		}
		return ssh2ciphersCS;
	}

	/**
	 * The supported SSH2 Hmacs.
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedHMacsSC() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) hmacsSC.clone();
		}
		return hmacsSC;
	}

	/**
	 * The supported SSH2 Hmacs.
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedHMacsCS() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) hmacsCS.clone();
		}
		return hmacsCS;
	}

	/**
	 * The supported SSH2 key exchanges.
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedKeyExchanges() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) keyexchange.clone();
		}
		return keyexchange;
	}

	/**
	 * The supported public keys
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedPublicKeys() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) publickeys.clone();
		}
		return publickeys;
	}

	/**
	 * The supported digests
	 * @return AbstractComponentFactory
	 */
	public ComponentFactory supportedDigests() {
		if(PerContextAlgorithmPreferences) {
			return (ComponentFactory) digests.clone();
		}
		return digests;
	}

	/**
	 * Generate an RSA public/private pair.
	 * @param bits
	 * @param version
	 * @return SshKeyPair
	 * @throws SshException
	 */
	public abstract SshKeyPair generateRsaKeyPair(int bits) throws SshException;

	/**
	 * Create an instance of an RSA public key.
	 * @param modulus
	 * @param publicExponent
	 * @param version
	 * @return SshRsaPublicKey
	 * @throws SshException
	 */
	public abstract SshRsaPublicKey createRsaPublicKey(BigInteger modulus, BigInteger publicExponent) throws SshException;

	/**
	 * Create an instance of an SSH2 RSA public key.
	 * @return SshRsaPublicKey
	 * @throws SshException
	 */
	public abstract SshRsaPublicKey createSsh2RsaPublicKey() throws SshException;

	/**
	 * Create an instance of an RSA private key.
	 * @param modulus
	 * @param privateExponent
	 * @return SshRsaPrivateKey
	 * @throws SshException
	 */
	public abstract SshRsaPrivateKey createRsaPrivateKey(BigInteger modulus, BigInteger privateExponent) throws SshException;

	/**
	 * Create an instance of an RSA co-effecient private key. 
	 * @param modulus
	 * @param publicExponent
	 * @param privateExponent
	 * @param primeP
	 * @param primeQ
	 * @param crtCoefficient
	 * @return SshRsaPrivateCrtKey
	 * @throws SshException
	 */
	public abstract SshRsaPrivateCrtKey createRsaPrivateCrtKey(BigInteger modulus,
                            BigInteger publicExponent,
                            BigInteger privateExponent,
                            BigInteger primeP,
                            BigInteger primeQ,
                            BigInteger crtCoefficient) throws SshException;

	/**
	 * Create an instance of an RSA co-efficent private key. 
	 * @param modulus
	 * @param publicExponent
	 * @param privateExponent
	 * @param primeP
	 * @param primeQ
	 * @param primeExponentP
	 * @param primeExponentQ
	 * @param crtCoefficient
	 * @return SshRsaPrivateCrtKey
	 * @throws SshException
	 */
	public abstract SshRsaPrivateCrtKey createRsaPrivateCrtKey(BigInteger modulus,
												    BigInteger publicExponent,
												    BigInteger privateExponent,
												    BigInteger primeP,
												    BigInteger primeQ,
												    BigInteger primeExponentP,
												    BigInteger primeExponentQ,
												    BigInteger crtCoefficient) throws SshException;

	/**
	 * Generate a new DSA public/private key pair.
	 * @param bits
	 * @return SshKeyPair
	 * @throws SshException
	 */
	public abstract SshKeyPair generateDsaKeyPair(int bits) throws SshException;

	/**
	 * Create an instance of a DSA public key.
	 * @param p
	 * @param q
	 * @param g
	 * @param y
	 * @return SshDsaPublicKey
	 * @throws SshException
	 */
	public abstract SshDsaPublicKey createDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) throws SshException;

	/**
	 * Create an uninitialized instance of a DSA public key
	 * @return SshDsaPublicKey
	 */
	public abstract SshDsaPublicKey createDsaPublicKey();

	/**
	 * Create an instance of a DSA private key. 
	 * @param p
	 * @param q
	 * @param g
	 * @param x
	 * @param y
	 * @return SshDsaPrivateKey
	 * @throws SshException
	 */
	public abstract SshDsaPrivateKey createDsaPrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) throws SshException;

	/**
	 * Get the secure random number generator. 
	 * @return SshSecureRandomGenerator
	 * @throws SshException
	 */
	public abstract SshSecureRandomGenerator getRND() throws SshException;

}

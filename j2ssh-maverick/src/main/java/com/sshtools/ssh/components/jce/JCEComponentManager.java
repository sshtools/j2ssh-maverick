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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import com.sshtools.logging.Log;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.ComponentFactory;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.Digest;
import com.sshtools.ssh.components.SshCipher;
import com.sshtools.ssh.components.SshDsaPrivateKey;
import com.sshtools.ssh.components.SshDsaPublicKey;
import com.sshtools.ssh.components.SshHmac;
import com.sshtools.ssh.components.SshKeyPair;
import com.sshtools.ssh.components.SshRsaPrivateCrtKey;
import com.sshtools.ssh.components.SshRsaPrivateKey;
import com.sshtools.ssh.components.SshRsaPublicKey;
import com.sshtools.ssh.components.SshSecureRandomGenerator;

/**
 * A component manager for the Java runtime JCE provider. By default all
 * algorithms will be selected from the default provider i.e no provider is
 * specified in calls to JCE methods to create components. You can initialize a
 * default provider to be used on all calls with the following code:
 * 
 * <blockquote>
 * 
 * <pre>
 * JCEComponentManager.initializeDefaultProvider(new BouncyCastleProvider());
 * </pre>
 * 
 * </blockquote>
 * 
 * Alternatively you can also assign a specific provider for an individual
 * algorithm, all algorithms used by the API are included as static constants in
 * this class.
 * 
 * <blockquote>
 * 
 * <pre>
 * JCEComponentManager.initializeProviderForAlgorithm(JCEComponentManager.JCE_DSA,
 * 		new BouncyCastleProvider());
 * </pre>
 * 
 * </blockquote>
 * 
 * @author Lee David Painter
 */
public class JCEComponentManager extends ComponentManager implements
		JCEAlgorithms {

	SecureRND rnd;

	public JCEComponentManager() {

		try {

			@SuppressWarnings("unchecked")
			Class<Provider> cls = (Class<Provider>) Class
					.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");

			Provider bc = (Provider) cls.newInstance();
			java.security.Security.addProvider(bc);

			JCEComponentManager.initializeProviderForAlgorithm(
					JCEAlgorithms.JCE_DH, bc);
		} catch (Throwable t) {
			Log.error(
					this,
					"Could not find BouncyCastle provider diffie-hellman-group14-sha1 may not be available");
		}

	}

	/**
	 * Initialize the default JCE provider used by the API.
	 * 
	 * @param provider
	 */
	public static void initializeDefaultProvider(Provider provider) {
		JCEProvider.initializeDefaultProvider(provider);
	}

	/**
	 * Initialize a provider for a specific algorithm.
	 * 
	 * @param jceAlgorithm
	 * @param provider
	 */
	public static void initializeProviderForAlgorithm(String jceAlgorithm,
			Provider provider) {
		JCEProvider.initializeProviderForAlgorithm(jceAlgorithm, provider);
	}

	/**
	 * Get the algorithm used for secure random number generation.
	 * 
	 * @return String
	 */
	public static String getSecureRandomAlgorithm() {
		return JCEProvider.getSecureRandomAlgorithm();
	}

	/**
	 * Set the algorithm used for secure random number generation.
	 * 
	 * @param secureRandomAlgorithm
	 */
	public static void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
		JCEProvider.setSecureRandomAlgorithm(secureRandomAlgorithm);
	}

	/**
	 * Get the provider for a specific algorithm.
	 * 
	 * @param jceAlgorithm
	 * @return Provider
	 */
	public static Provider getProviderForAlgorithm(String jceAlgorithm) {
		return JCEProvider.getProviderForAlgorithm(jceAlgorithm);
	}

	/**
	 * Get the secure random implementation for the API.
	 * 
	 * @return SecureRandom
	 * @throws NoSuchAlgorithmException
	 */
	public static SecureRandom getSecureRandom()
			throws NoSuchAlgorithmException {
		return JCEProvider.getSecureRandom();
	}

	public SshDsaPrivateKey createDsaPrivateKey(BigInteger p, BigInteger q,
			BigInteger g, BigInteger x, BigInteger y) throws SshException {
		return new Ssh2DsaPrivateKey(p, q, g, x, y);
	}

	public SshDsaPublicKey createDsaPublicKey(BigInteger p, BigInteger q,
			BigInteger g, BigInteger y) throws SshException {
		try {
			return new Ssh2DsaPublicKey(p, q, g, y);
		} catch (Throwable e) {
			throw new SshException(e);
		}
	}

	public SshDsaPublicKey createDsaPublicKey() {
		return new Ssh2DsaPublicKey();
	}

	public SshRsaPrivateCrtKey createRsaPrivateCrtKey(BigInteger modulus,
			BigInteger publicExponent, BigInteger privateExponent,
			BigInteger primeP, BigInteger primeQ, BigInteger crtCoefficient)
			throws SshException {

		try {
			BigInteger primeExponentP = primeP.subtract(BigInteger.ONE);
			primeExponentP = privateExponent.mod(primeExponentP);

			BigInteger primeExponentQ = primeQ.subtract(BigInteger.ONE);
			primeExponentQ = privateExponent.mod(primeExponentQ);

			return new Ssh2RsaPrivateCrtKey(modulus, publicExponent,
					privateExponent, primeP, primeQ, primeExponentP,
					primeExponentQ, crtCoefficient);
		} catch (Throwable e) {
			throw new SshException(e);
		}
	}

	public SshRsaPrivateCrtKey createRsaPrivateCrtKey(BigInteger modulus,
			BigInteger publicExponent, BigInteger privateExponent,
			BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP,
			BigInteger primeExponentQ, BigInteger crtCoefficient)
			throws SshException {
		try {
			return new Ssh2RsaPrivateCrtKey(modulus, publicExponent,
					privateExponent, primeP, primeQ, primeExponentP,
					primeExponentQ, crtCoefficient);
		} catch (Throwable e) {
			throw new SshException(e);
		}
	}

	public SshRsaPrivateKey createRsaPrivateKey(BigInteger modulus,
			BigInteger privateExponent) throws SshException {
		try {
			return new Ssh2RsaPrivateKey(modulus, privateExponent);
		} catch (Throwable t) {
			throw new SshException(t);
		}
	}

	public SshRsaPublicKey createRsaPublicKey(BigInteger modulus,
			BigInteger publicExponent) throws SshException {
		try {
			return new Ssh2RsaPublicKey(modulus, publicExponent);
		} catch (Throwable e) {
			throw new SshException(e);
		}
	}

	public SshRsaPublicKey createSsh2RsaPublicKey() throws SshException {
		return new Ssh2RsaPublicKey();
	}

	public SshKeyPair generateDsaKeyPair(int bits) throws SshException {

		try {

			KeyPairGenerator keyGen = JCEProvider
					.getProviderForAlgorithm(JCE_DSA) == null ? KeyPairGenerator
					.getInstance(JCE_DSA) : KeyPairGenerator.getInstance(
					JCE_DSA, JCEProvider.getProviderForAlgorithm(JCE_DSA));
			keyGen.initialize(bits);
			KeyPair keypair = keyGen.genKeyPair();
			PrivateKey privateKey = keypair.getPrivate();
			PublicKey publicKey = keypair.getPublic();

			SshKeyPair pair = new SshKeyPair();

			pair.setPrivateKey(new Ssh2DsaPrivateKey(
					(DSAPrivateKey) privateKey, (DSAPublicKey) publicKey));
			pair.setPublicKey(new Ssh2DsaPublicKey((DSAPublicKey) publicKey));
			return pair;
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new SshException(e);
		}
	}

	public SshKeyPair generateRsaKeyPair(int bits) throws SshException {
		try {

			KeyPairGenerator keyGen = JCEProvider
					.getProviderForAlgorithm(JCE_RSA) == null ? KeyPairGenerator
					.getInstance(JCE_RSA) : KeyPairGenerator.getInstance(
					JCE_RSA, JCEProvider.getProviderForAlgorithm(JCE_RSA));
			keyGen.initialize(bits);
			KeyPair keypair = keyGen.genKeyPair();
			PrivateKey privateKey = keypair.getPrivate();
			PublicKey publicKey = keypair.getPublic();

			SshKeyPair pair = new SshKeyPair();
			if (!(privateKey instanceof RSAPrivateCrtKey)) {
				throw new SshException(
						"RSA key generation requires RSAPrivateCrtKey as private key type.",
						SshException.JCE_ERROR);
			}
			pair.setPrivateKey(new Ssh2RsaPrivateCrtKey(
					(RSAPrivateCrtKey) privateKey));
			pair.setPublicKey(new Ssh2RsaPublicKey((RSAPublicKey) publicKey));

			return pair;
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new SshException(e);
		}
	}

	public SshSecureRandomGenerator getRND() throws SshException {
		try {
			return rnd == null ? new SecureRND() : rnd;
		} catch (NoSuchAlgorithmException e) {
			throw new SshException(e);
		}
	}

	protected void initializeDigestFactory(ComponentFactory digests) {

		if (testDigest(JCEAlgorithms.JCE_MD5, MD5Digest.class))
			digests.add(JCEAlgorithms.JCE_MD5, MD5Digest.class);

		if (testDigest(JCEAlgorithms.JCE_SHA1, SHA1Digest.class))
			digests.add(JCEAlgorithms.JCE_SHA1, SHA1Digest.class);

		if (testDigest("SHA1", SHA1Digest.class))
			digests.add("SHA1", SHA1Digest.class);

		if (testDigest("SHA-256", SHA256Digest.class))
			digests.add("SHA-256", SHA256Digest.class);
	}

	protected void initializeHmacFactory(ComponentFactory hmacs) {

		if (testHMac("hmac-md5", HmacMD5.class))
			hmacs.add("hmac-md5", HmacMD5.class);

		if (testHMac("hmac-sha1", HmacSha1.class))
			hmacs.add("hmac-sha1", HmacSha1.class);

		if (testHMac("hmac-md5-96", HmacMD596.class))
			hmacs.add("hmac-md5-96", HmacMD596.class);

		if (testHMac("hmac-sha1-96", HmacSha196.class))
			hmacs.add("hmac-sha1-96", HmacSha196.class);

		if (testHMac("hmac-sha256", HmacSha256.class)) {
			hmacs.add("hmac-sha256", HmacSha256.class);
			hmacs.add("hmac-sha2-256", HmacSha256.class);
			hmacs.add("hmac-sha256@ssh.com", HmacSha256.class);
		}

		// if(testHMac("hmac-sha512", HmacSha512.class)) {
		// hmacs.add("hmac-sha512", HmacSha512.class);
		// hmacs.add("hmac-sha512@ssh.com", HmacSha512.class);
		// }

	}

	protected void initializeKeyExchangeFactory(ComponentFactory keyexchange) {
		// sshd has its own version of these classes so they will not be on its
		// classpath, this is why we use class.forname
		try {
			Class<?> DiffieHellmanGroup14Sha1 = Class
					.forName("com.maverick.ssh.components.jce.DiffieHellmanGroup14Sha1");
			Class<?> DiffieHellmanGroup1Sha1 = Class
					.forName("com.maverick.ssh.components.jce.DiffieHellmanGroup1Sha1");
			Class<?> DiffieHellmanGroupExchangeSha1 = Class
					.forName("com.maverick.ssh.components.jce.DiffieHellmanGroupExchangeSha1");
			Class<?> DiffieHellmanGroupExchangeSha256 = Class
					.forName("com.maverick.ssh.components.jce.DiffieHellmanGroupExchangeSha256");

			if (testKeyExchangeAlgorithm("diffie-hellman-group14-sha1",
					DiffieHellmanGroup14Sha1)) {
				keyexchange.add("diffie-hellman-group14-sha1",
						DiffieHellmanGroup14Sha1);
			}

			if (testKeyExchangeAlgorithm("diffie-hellman-group1-sha1",
					DiffieHellmanGroup1Sha1)) {
				keyexchange.add("diffie-hellman-group1-sha1",
						DiffieHellmanGroup1Sha1);
			}

			if (testKeyExchangeAlgorithm("diffie-hellman-group-exchange-sha1",
					DiffieHellmanGroupExchangeSha1)) {
				keyexchange.add("diffie-hellman-group-exchange-sha1",
						DiffieHellmanGroupExchangeSha1);
			}

			if (testKeyExchangeAlgorithm(
					"diffie-hellman-group-exchange-sha256",
					DiffieHellmanGroupExchangeSha256)) {
				keyexchange.add("diffie-hellman-group-exchange-sha256",
						DiffieHellmanGroupExchangeSha256);
			}

		} catch (ClassNotFoundException e) {
			// This is expected for SSHD
		}
	}

	protected void initializePublicKeyFactory(ComponentFactory publickeys) {
		publickeys.add("ssh-dss", Ssh2DsaPublicKey.class);
		publickeys.add("ssh-rsa", Ssh2RsaPublicKey.class);
		publickeys.add(SshX509RsaPublicKey.X509V3_SIGN_RSA,
				SshX509RsaPublicKey.class);
		publickeys.add(SshX509DsaPublicKey.X509V3_SIGN_DSA,
				SshX509DsaPublicKey.class);
		publickeys.add(SshX509RsaSha1PublicKey.X509V3_SIGN_RSA_SHA1,
				SshX509RsaSha1PublicKey.class);
	}

	protected void initializeSsh2CipherFactory(ComponentFactory ciphers) {

		if (testJCECipher("3des-ctr", TripleDesCtr.class)) {
			ciphers.add("3des-ctr", TripleDesCtr.class);
		}

		if (testJCECipher("aes128-ctr", AES128Ctr.class)) {
			ciphers.add("aes128-ctr", AES128Ctr.class);
		}

		if (testJCECipher("aes192-ctr", AES192Ctr.class)) {
			ciphers.add("aes192-ctr", AES192Ctr.class);
		}

		if (testJCECipher("aes256-ctr", AES256Ctr.class)) {
			ciphers.add("aes256-ctr", AES256Ctr.class);
		}

		if (testJCECipher("3des-cbc", TripleDesCbc.class)) {
			ciphers.add("3des-cbc", TripleDesCbc.class);
		}

		if (testJCECipher("blowfish-cbc", BlowfishCbc.class)) {
			ciphers.add("blowfish-cbc", BlowfishCbc.class);
		}

		if (testJCECipher("aes128-cbc", AES128Cbc.class)) {
			ciphers.add("aes128-cbc", AES128Cbc.class);
		}

		if (testJCECipher("aes192-cbc", AES192Cbc.class)) {
			ciphers.add("aes192-cbc", AES192Cbc.class);
		}

		if (testJCECipher("aes256-cbc", AES256Cbc.class)) {
			ciphers.add("aes256-cbc", AES256Cbc.class);
		}

		if (testJCECipher("arcfour", ArcFour.class)) {
			ciphers.add("arcfour", ArcFour.class);
		}

		if (testJCECipher("arcfour128", ArcFour128.class)) {
			ciphers.add("arcfour128", ArcFour128.class);
		}

		if (testJCECipher("arcfour256", ArcFour256.class)) {
			ciphers.add("arcfour256", ArcFour256.class);
		}

	}

	private boolean testKeyExchangeAlgorithm(String name,
			Class<?> keyExchangeAlgorithmClass) {

		String provider = "[unknown]";
		Object SshKeyExchangeClient_Instance = null;

		try {
			String clientId = "SSH-2.0-SOFTWARE_VERSION_COMMENTS";
			String serverId = "SSH-2.0-ExampleSSHD_1.2.3_Comments";

			byte[] clientKexInit = { 20, 9, 23, -34, -78, 80, 43, 43, -33, -62,
					73, 10, 4, 125, -72, -88, -20, 0, 0, 0, 27, 100, 105, 102,
					102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110, 45,
					103, 114, 111, 117, 112, 49, 52, 45, 115, 104, 97, 49, 0,
					0, 0, 15, 115, 115, 104, 45, 100, 115, 115, 44, 115, 115,
					104, 45, 114, 115, 97, 0, 0, 0, 32, 97, 101, 115, 49, 50,
					56, 45, 99, 98, 99, 44, 51, 100, 101, 115, 45, 99, 98, 99,
					44, 98, 108, 111, 119, 102, 105, 115, 104, 45, 99, 98, 99,
					0, 0, 0, 32, 97, 101, 115, 49, 50, 56, 45, 99, 98, 99, 44,
					51, 100, 101, 115, 45, 99, 98, 99, 44, 98, 108, 111, 119,
					102, 105, 115, 104, 45, 99, 98, 99, 0, 0, 0, 18, 104, 109,
					97, 99, 45, 115, 104, 97, 49, 44, 104, 109, 97, 99, 45,
					109, 100, 53, 0, 0, 0, 18, 104, 109, 97, 99, 45, 115, 104,
					97, 49, 44, 104, 109, 97, 99, 45, 109, 100, 53, 0, 0, 0, 9,
					110, 111, 110, 101, 44, 122, 108, 105, 98, 0, 0, 0, 9, 110,
					111, 110, 101, 44, 122, 108, 105, 98, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0 };
			byte[] serverKexInit = { 20, 23, 119, -40, -10, 11, -1, -102, 84,
					-3, 119, 47, -92, 81, 17, -51, -53, 0, 0, 0, 54, 100, 105,
					102, 102, 105, 101, 45, 104, 101, 108, 108, 109, 97, 110,
					45, 103, 114, 111, 117, 112, 49, 45, 115, 104, 97, 49, 44,
					100, 105, 102, 102, 105, 101, 45, 104, 101, 108, 108, 109,
					97, 110, 45, 103, 114, 111, 117, 112, 49, 52, 45, 115, 104,
					97, 49, 0, 0, 0, 15, 115, 115, 104, 45, 100, 115, 115, 44,
					115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 111, 97, 101,
					115, 49, 50, 56, 45, 99, 98, 99, 44, 51, 100, 101, 115, 45,
					99, 98, 99, 44, 98, 108, 111, 119, 102, 105, 115, 104, 45,
					99, 98, 99, 44, 97, 101, 115, 49, 57, 50, 45, 99, 98, 99,
					44, 97, 101, 115, 50, 53, 54, 45, 99, 98, 99, 44, 116, 119,
					111, 102, 105, 115, 104, 49, 50, 56, 45, 99, 98, 99, 44,
					116, 119, 111, 102, 105, 115, 104, 49, 57, 50, 45, 99, 98,
					99, 44, 116, 119, 111, 102, 105, 115, 104, 50, 53, 54, 45,
					99, 98, 99, 44, 99, 97, 115, 116, 49, 50, 56, 45, 99, 98,
					99, 0, 0, 0, 111, 97, 101, 115, 49, 50, 56, 45, 99, 98, 99,
					44, 51, 100, 101, 115, 45, 99, 98, 99, 44, 98, 108, 111,
					119, 102, 105, 115, 104, 45, 99, 98, 99, 44, 97, 101, 115,
					49, 57, 50, 45, 99, 98, 99, 44, 97, 101, 115, 50, 53, 54,
					45, 99, 98, 99, 44, 116, 119, 111, 102, 105, 115, 104, 49,
					50, 56, 45, 99, 98, 99, 44, 116, 119, 111, 102, 105, 115,
					104, 49, 57, 50, 45, 99, 98, 99, 44, 116, 119, 111, 102,
					105, 115, 104, 50, 53, 54, 45, 99, 98, 99, 44, 99, 97, 115,
					116, 49, 50, 56, 45, 99, 98, 99, 0, 0, 0, 43, 104, 109, 97,
					99, 45, 115, 104, 97, 49, 44, 104, 109, 97, 99, 45, 109,
					100, 53, 44, 104, 109, 97, 99, 45, 109, 100, 53, 45, 57,
					54, 44, 104, 109, 97, 99, 45, 115, 104, 97, 49, 45, 57, 54,
					0, 0, 0, 43, 104, 109, 97, 99, 45, 115, 104, 97, 49, 44,
					104, 109, 97, 99, 45, 109, 100, 53, 44, 104, 109, 97, 99,
					45, 109, 100, 53, 45, 57, 54, 44, 104, 109, 97, 99, 45,
					115, 104, 97, 49, 45, 57, 54, 0, 0, 0, 9, 110, 111, 110,
					101, 44, 122, 108, 105, 98, 0, 0, 0, 9, 110, 111, 110, 101,
					44, 122, 108, 105, 98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0 };

			SshKeyExchangeClient_Instance = keyExchangeAlgorithmClass
					.newInstance();
			Method test = keyExchangeAlgorithmClass.getMethod(
					"performClientExchange", new Class[] { String.class,
							String.class, byte[].class, byte[].class });
			test.invoke(SshKeyExchangeClient_Instance, new Object[] { clientId,
					serverId, clientKexInit, serverKexInit });

		} catch (InvocationTargetException e) {
			if (e.getCause() instanceof SshException) {
				if (e.getCause().getCause() instanceof NoSuchAlgorithmException) {
					Log.info(this, "   " + name
							+ " will not be supported: "
							+ e.getCause().getCause().getMessage());
					return false;
				} else if (e.getCause().getCause() instanceof InvalidAlgorithmParameterException) {
					Log.info(this, "   " + name
							+ " will not be supported: "
							+ e.getCause().getCause().getMessage());
					return false;
				}
			}
		} catch (Throwable e) {
			// a null pointer exception will be caught at the end of the keyex
			// call when transport.sendmessage is called, at this point the
			// algorithm has not thrown an exception so we ignore this excpected
			// exception.
		}

		try {
			Method test = keyExchangeAlgorithmClass.getMethod("getProvider",
					new Class[] {});
			provider = (String) test.invoke(SshKeyExchangeClient_Instance,
					new Object[] {});
		} catch (Throwable t) {
		}

		Log.info(this, "   " + name
				+ " will be supported using JCEProvider " + provider);
		return true;
	}

	private boolean testJCECipher(String name, Class<?> cls) {
		try {
			SshCipher c = (SshCipher) cls.newInstance();
			byte[] tmp = new byte[1024];
			c.init(SshCipher.ENCRYPT_MODE, tmp, tmp);

			if (c instanceof AbstractJCECipher)
				Log.info(this, "   " + name
						+ " will be supported using JCE Provider "
						+ ((AbstractJCECipher) c).getProvider());

			return true;
		} catch (Throwable e) {
			Log.info(this, "   " + name + " will not be supported: "
					+ e.getMessage());
			return false;
		}
	}

	private boolean testDigest(String name, Class<?> cls) {
		try {
			Digest c = (Digest) cls.newInstance();

			if (c instanceof AbstractDigest)
				Log.info(this, "   " + name
						+ " will be supported using JCE Provider "
						+ ((AbstractDigest) c).getProvider());

			return true;
		} catch (Throwable e) {
			Log.info(this, "   " + name + " will not be supported: "
					+ e.getMessage());
			return false;
		}
	}

	private boolean testHMac(String name, Class<?> cls) {
		try {
			SshHmac c = (SshHmac) cls.newInstance();
			byte[] tmp = new byte[1024];
			c.init(tmp);

			if (c instanceof AbstractHmac)
				Log.info(this, "   " + name
						+ " will be supported using JCE Provider "
						+ ((AbstractHmac) c).getProvider());

			return true;
		} catch (Throwable e) {
			Log.info(this, "   " + name + " will not be supported: "
					+ e.getMessage());
			return false;
		}
	}
}

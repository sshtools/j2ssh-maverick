/**
 * Copyright 2003-2016 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.ssh2;

import java.util.Vector;

import com.sshtools.logging.Log;
import com.sshtools.ssh.ForwardingRequestListener;
import com.sshtools.ssh.HostKeyVerification;
import com.sshtools.ssh.SshConnector;
import com.sshtools.ssh.SshContext;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.ComponentFactory;
import com.sshtools.ssh.components.ComponentManager;

/**
 * <p>
 * This class implements <a href="../ssh/SshContext.html">SshContext</a>to
 * provide SSH2 connection configuration through the <a
 * href="../ssh/SshConnector.html">SshConnector</a> class.
 * </p>
 * 
 * <p>
 * To configure an authentication banner for SSH2 connections see <a
 * href="BannerDisplay.html">BannerDisplay</a>.
 * </p>
 * 
 * <p>
 * The preferred message authentication algorithm for each data stream can be
 * set using: <blockquote>
 * 
 * <pre>
 * SshConnector con = SshConnector.getInstance();
 * Ssh2Context context = (Ssh2Context) con.getContext(SshConnector.SSH2);
 * 
 * context.setPreferredMacCS(Ssh2Context.HMAC_MD5); // Client-&gt;Server data stream
 * context.setPreferredMacSC(Ssh2Context.HMAC_MD5); // Server-&gt;Client data stream
 * </pre>
 * 
 * </blockquote> Once further cipher, public key and compression algorithms have
 * been implemented the same process will apply.
 * </p>
 * 
 * @author Lee David Painter
 */
public final class Ssh2Context implements SshContext {

	ComponentFactory compressionsCS;
	ComponentFactory compressionsSC;
	ComponentFactory ciphersCS;
	ComponentFactory ciphersSC;
	ComponentFactory keyExchanges;
	ComponentFactory macCS;
	ComponentFactory macSC;
	ComponentFactory publicKeys;

	public static final String CIPHER_TRIPLEDES_CBC = "3des-cbc";

	public static final String CIPHER_TRIPLEDES_CTR = "3des-ctr";

	public static final String CIPHER_BLOWFISH_CBC = "blowfish-cbc";

	public static final String CIPHER_AES128_CBC = "aes128-cbc";

	public static final String CIPHER_AES192_CBC = "aes192-cbc";

	public static final String CIPHER_AES256_CBC = "aes256-cbc";

	public static final String CIPHER_AES128_CTR = "aes128-ctr";

	public static final String CIPHER_AES192_CTR = "aes192-ctr";

	public static final String CIPHER_AES256_CTR = "aes256-ctr";

	public static final String CIPHER_ARCFOUR = "arcfour";

	public static final String CIPHER_ARCFOUR_128 = "arcfour128";

	public static final String CIPHER_ARCFOUR_256 = "arcfour256";

	/** SHA1 message authentication **/
	public static final String HMAC_SHA1 = "hmac-sha1";

	/** SHA1 96 bit message authentication **/
	public static final String HMAC_SHA1_96 = "hmac-sha1-96";

	/** MD5 message authentication **/
	public static final String HMAC_MD5 = "hmac-md5";

	/** MD5 96 bit message authentication **/
	public static final String HMAC_MD5_96 = "hmac-md5-96";

	public static final String HMAC_SHA256 = "hmac-sha256";

	/** Compression off **/
	public static final String COMPRESSION_NONE = "none";

	/** Optional zlib compression (requires sshtools-zlib.jar in classpath) */
	public static final String COMPRESSION_ZLIB = "zlib";

	/** The required key exchange method **/
	public static final String KEX_DIFFIE_HELLMAN_GROUP1_SHA1 = "diffie-hellman-group1-sha1";

	public static final String KEX_DIFFIE_HELLMAN_GROUP14_SHA1 = "diffie-hellman-group14-sha1";

	/**
	 * Optional key exchange mechanism in which the server maintains a list of
	 * acceptable generators and primes
	 **/
	public static final String KEX_DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = "diffie-hellman-group-exchange-sha1";

	public static final String KEX_DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 = "diffie-hellman-group-exchange-sha256";

	public static final String KEX_DIFFIE_HELLMAN_ECDH_NISTP_256 = "ecdh-sha2-nistp256";
	public static final String KEX_DIFFIE_HELLMAN_ECDH_NISTP_384 = "ecdh-sha2-nistp384";
	public static final String KEX_DIFFIE_HELLMAN_ECDH_NISTP_521 = "ecdh-sha2-nistp521";
	
	/** SSH2 DSA Public Key **/
	public static final String PUBLIC_KEY_SSHDSS = "ssh-dss";

	/** SSH2 RSA Public Key **/
	public static final String PUBLIC_KEY_SSHRSA = "ssh-rsa";

	public static final String PUBLIC_KEY_ECDSA_256 = "ecdsa-sha2-nistp256";
	public static final String PUBLIC_KEY_ECDSA_384 = "ecdsa-sha2-nistp384";
	public static final String PUBLIC_KEY_ECDSA_521 = "ecdsa-sha2-nistp521";
	
	String prefCipherCS = CIPHER_AES128_CTR;
	String prefCipherSC = CIPHER_AES128_CTR;

	String prefMacCS = HMAC_SHA1;
	String prefMacSC = HMAC_SHA1;

	String prefCompressionCS = COMPRESSION_NONE;
	String prefCompressionSC = COMPRESSION_NONE;

	String prefKeyExchange = KEX_DIFFIE_HELLMAN_ECDH_NISTP_256;
	String prefPublicKey = PUBLIC_KEY_ECDSA_256;

	String sftpProvider = "/usr/libexec/sftp-server";

	int maxChannels = 100;

	BannerDisplay bannerdisplay;
	HostKeyVerification verify;

	String xDisplay = null;
	byte[] x11FakeCookie = null;
	byte[] x11RealCookie = null;
	ForwardingRequestListener x11Listener = null;

	String jceProvider = "";
	int maxPacketLength = 131072;

	boolean keyReExchangeDisabled = false;

	int partialMessageTimeout = 30000;
	int keepAliveMaxDataLength = 128;
	int idleConnectionTimeoutSeconds = 0;
	boolean sendIgnorePacketOnIdle = false;

	int dhGroupExchangeKeySize = 1024;
	boolean dhGroupExchangeBackwardCompatible = false;

	int socketTimeout = 0;
	SshConnector con;

	/**
	 * Contructs a default context
	 * 
	 * @throws SshException
	 */
	public Ssh2Context() throws SshException {

		try {
			ciphersCS = ComponentManager.getInstance().supportedSsh2CiphersCS();
			ciphersSC = ComponentManager.getInstance().supportedSsh2CiphersSC();
			keyExchanges = ComponentManager.getInstance()
					.supportedKeyExchanges();
			macCS = ComponentManager.getInstance().supportedHMacsCS();
			macSC = ComponentManager.getInstance().supportedHMacsSC();
			publicKeys = ComponentManager.getInstance().supportedPublicKeys();

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Creating compression factory");
			}

			compressionsSC = new ComponentFactory(
					Class.forName("com.sshtools.ssh.compression.SshCompression"));

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Adding None Compression");
			}
			compressionsSC.add(COMPRESSION_NONE,
					Class.forName("java.lang.Object" /* We never use it */));
			try {
				if (Log.isDebugEnabled()) {
					Log.debug(this, "Adding ZLib Compression");
				}
				compressionsSC.add("zlib",
						Class.forName("com.sshtools.zlib.ZLibCompression"));
				compressionsSC.add("zlib@openssh.com", Class
						.forName("com.sshtools.zlib.OpenSSHZLibCompression"));
			} catch (Throwable t) {
			}

			compressionsCS = new ComponentFactory(
					Class.forName("com.sshtools.ssh.compression.SshCompression"));

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Adding None Compression");
			}
			compressionsCS.add(COMPRESSION_NONE,
					Class.forName("java.lang.Object" /* We never use it */));
			try {
				if (Log.isDebugEnabled()) {
					Log.debug(this, "Adding ZLib Compression");
				}
				compressionsCS.add("zlib",
						Class.forName("com.sshtools.zlib.ZLibCompression"));
				compressionsCS.add("zlib@openssh.com", Class
						.forName("com.sshtools.zlib.OpenSSHZLibCompression"));

			} catch (Throwable t) {
			}

		} catch (Throwable t) {
			t.printStackTrace();
			throw new SshException(t.getMessage() != null ? t.getMessage() : t
					.getClass().getName(), SshException.INTERNAL_ERROR); // SSHException
		}

		if (Log.isDebugEnabled()) {
			Log.debug(this, "Completed Ssh2Context creation");
		}
	}

	/**
	 * Get the maximim packet size supported by the transport layer.
	 * 
	 * @return int
	 */
	public int getMaximumPacketLength() {
		return maxPacketLength;
	}

	MaverickCallbackHandler gsscall = null;

	public void setGssCallback(MaverickCallbackHandler gsscall) {
		this.gsscall = gsscall;
	}

	public MaverickCallbackHandler getGssCallback() {
		return gsscall;
	}

	/**
	 * Set the maximum packet size supported by the transport layer. This would
	 * not normally require changing but some servers may support larger
	 * packets. The default and minimum size is 35,000 bytes.
	 * 
	 * @param maxPacketLength
	 *            int
	 */
	public void setMaximumPacketLength(int maxPacketLength) {
		if (maxPacketLength < 35000)
			throw new IllegalArgumentException(
					"The minimum packet length supported must be 35,000 bytes or greater!");
		this.maxPacketLength = maxPacketLength;
	}

	public void setChannelLimit(int maxChannels) {
		this.maxChannels = maxChannels;
	}

	public int getChannelLimit() {
		return maxChannels;
	}

	public void setX11Display(String xDisplay) {
		this.xDisplay = xDisplay;
	}

	public String getX11Display() {
		return xDisplay;
	}

	public byte[] getX11AuthenticationCookie() throws SshException {
		if (x11FakeCookie == null) {
			x11FakeCookie = new byte[16];
			ComponentManager.getInstance().getRND().nextBytes(x11FakeCookie);
		}
		return x11FakeCookie;
	}

	public void setX11AuthenticationCookie(byte[] x11FakeCookie) {
		this.x11FakeCookie = x11FakeCookie;
	}

	public void setX11RealCookie(byte[] x11RealCookie) {
		this.x11RealCookie = x11RealCookie;
	}

	public byte[] getX11RealCookie() throws SshException {
		if (x11RealCookie == null) {
			x11RealCookie = getX11AuthenticationCookie();
		}
		return x11RealCookie;
	}

	public void setX11RequestListener(ForwardingRequestListener x11Listener) {
		this.x11Listener = x11Listener;
	}

	public ForwardingRequestListener getX11RequestListener() {
		return x11Listener;
	}

	/**
	 * Get the contexts banner display
	 * 
	 * @return the banner display, may be null
	 */
	public BannerDisplay getBannerDisplay() {
		return bannerdisplay;
	}

	/**
	 * Set a banner display for callback of authentication banners
	 * 
	 * @param bannerdisplay
	 *            the banner display, may be null
	 */
	public void setBannerDisplay(BannerDisplay bannerdisplay) {
		this.bannerdisplay = bannerdisplay;
	}

	/**
	 * Returns this context's supported cipher algorithms.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedCiphersSC() {
		return ciphersSC;
	}

	public ComponentFactory supportedCiphersCS() {
		return ciphersCS;
	}

	/**
	 * Get the currently preferred cipher for the Client->Server stream.
	 * 
	 * @return the preferred Client-Server cipher
	 */
	public String getPreferredCipherCS() {
		return prefCipherCS;
	}

	/**
	 * Set the preferred cipher for the Client->Server stream.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredCipherCS(String name) throws SshException {

		if (name == null)
			return;

		if (ciphersCS.contains(name)) {
			prefCipherCS = name;
			setCipherPreferredPositionCS(name, 0);
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Get the currently preferred cipher for the Server->Client stream.
	 * 
	 * @return the preferred Server-Client cipher
	 */
	public String getPreferredCipherSC() {
		return prefCipherSC;
	}

	/**
	 * Get the ciphers for the Client->Server stream.
	 * 
	 * @return the Client-Server ciphers in order of preference
	 */
	public String getCiphersCS() {
		return ciphersCS.list(prefCipherCS);
	}

	/**
	 * Get the ciphers for the Server->Client stream.
	 * 
	 * @return the Server-Client ciphers in order of preference
	 */
	public String getCiphersSC() {
		return ciphersSC.list(prefCipherSC);
	}

	/**
	 * Get the ciphers for the Client->Server stream.
	 * 
	 * @return the Client-Server ciphers in order of preference
	 */
	public String getMacsCS() {
		return macCS.list(prefMacCS);
	}

	/**
	 * Get the ciphers for the Server->Client stream.
	 * 
	 * @return the Server-Client ciphers in order of preference
	 */
	public String getMacsSC() {
		return macSC.list(prefMacSC);
	}

	/**
	 * Get the ciphers for the Server->Client stream.
	 * 
	 * @return the Server-Client ciphers in order of preference
	 */
	public String getPublicKeys() {
		return publicKeys.list(prefPublicKey);
	}

	/**
	 * Get the ciphers for the Server->Client stream.
	 * 
	 * @return the Server-Client ciphers in order of preference
	 */
	public String getKeyExchanges() {
		return keyExchanges.list(prefKeyExchange);
	}

	/**
	 * Set the preferred SC cipher order
	 * 
	 * @param order
	 *            , list of indices to be moved to the top.
	 * @throws SshException
	 */
	public void setPreferredCipherSC(int[] order) throws SshException {
		prefCipherSC = ciphersSC.createNewOrdering(order);
	}

	/**
	 * Set the preferred SC cipher order
	 * 
	 * @param order
	 *            , list of indices to be moved to the top.
	 * @throws SshException
	 */
	public void setPreferredCipherCS(int[] order) throws SshException {
		prefCipherCS = ciphersCS.createNewOrdering(order);
	}

	public void setCipherPreferredPositionCS(String name, int position)
			throws SshException {
		prefCipherCS = ciphersCS.changePositionofAlgorithm(name, position);
	}

	public void setCipherPreferredPositionSC(String name, int position)
			throws SshException {
		prefCipherSC = ciphersSC.changePositionofAlgorithm(name, position);
	}

	public void setMacPreferredPositionSC(String name, int position)
			throws SshException {
		prefMacSC = macSC.changePositionofAlgorithm(name, position);
	}

	public void setMacPreferredPositionCS(String name, int position)
			throws SshException {
		prefMacCS = macCS.changePositionofAlgorithm(name, position);
	}

	/**
	 * Set the preferred SC Mac order
	 * 
	 * @param order
	 *            , list of indices to be moved to the top.
	 * @throws SshException
	 */
	public void setPreferredMacSC(int[] order) throws SshException {
		prefCipherSC = macSC.createNewOrdering(order);
	}

	/**
	 * Set the preferred CS Mac order
	 * 
	 * @param order
	 *            , list of indices to be moved to the top.
	 * @throws SshException
	 */
	public void setPreferredMacCS(int[] order) throws SshException {
		prefCipherSC = macCS.createNewOrdering(order);
	}

	/**
	 * Set the preferred cipher for the Server->Client stream.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredCipherSC(String name) throws SshException {

		if (name == null)
			return;

		if (ciphersSC.contains(name)) {
			prefCipherSC = name;
			setCipherPreferredPositionSC(name, 0);
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Get this context's supported message authentication algorithms SC.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedMacsSC() {
		return macSC;
	}

	/**
	 * Get this context's supported message authentication algorithms CS.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedMacsCS() {
		return macCS;
	}

	/**
	 * Get the currently preferred mac for the Client->Server stream.
	 * 
	 * @return the preferred Client-Server mac
	 */
	public String getPreferredMacCS() {
		return prefMacCS;
	}

	/**
	 * Set the preferred mac for the Client->Server stream.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredMacCS(String name) throws SshException {

		if (name == null)
			return;

		if (macCS.contains(name)) {
			prefMacCS = name;
			setMacPreferredPositionCS(name, 0);
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Get the currently supported mac for the Server-Client stream.
	 * 
	 * @return the preferred Server-Client mac
	 */
	public String getPreferredMacSC() {
		return prefMacSC;
	}

	/**
	 * Set the preferred mac for the Server->Client stream.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredMacSC(String name) throws SshException {

		if (name == null)
			return;

		if (macSC.contains(name)) {
			prefMacSC = name;
			setMacPreferredPositionSC(name, 0);
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Get this context's supported SC compression algorithms.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedCompressionsSC() {
		return compressionsSC;
	}

	/**
	 * Get this context's supported CS compression algorithms.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedCompressionsCS() {
		return compressionsCS;
	}

	/**
	 * Get the currently preferred compression for the Client->Server stream.
	 * 
	 * @return the preferred Client-Server compression
	 */
	public String getPreferredCompressionCS() {
		return prefCompressionCS;
	}

	/**
	 * Set the preferred compression for the Client->Server stream.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredCompressionCS(String name) throws SshException {

		if (name == null)
			return;

		if (compressionsCS.contains(name)) {
			prefCompressionCS = name;
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Get the currently preferred compression for the Server->Client stream.
	 * 
	 * @return the preferred Server->Client compression
	 */
	public String getPreferredCompressionSC() {
		return prefCompressionSC;
	}

	/**
	 * Set the preferred compression for the Server->Client stream.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredCompressionSC(String name) throws SshException {

		if (name == null)
			return;

		if (compressionsSC.contains(name)) {
			prefCompressionSC = name;
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	public void enableCompression() throws SshException {

		supportedCompressionsCS().changePositionofAlgorithm("zlib", 0);
		supportedCompressionsCS().changePositionofAlgorithm("zlib@openssh.com",
				1);
		prefCompressionCS = supportedCompressionsCS()
				.changePositionofAlgorithm("none", 2);

		supportedCompressionsSC().changePositionofAlgorithm("zlib", 0);
		supportedCompressionsSC().changePositionofAlgorithm("zlib@openssh.com",
				1);
		prefCompressionSC = supportedCompressionsSC()
				.changePositionofAlgorithm("none", 2);

	}

	public void disableCompression() throws SshException {

		supportedCompressionsCS().changePositionofAlgorithm("none", 0);
		supportedCompressionsCS().changePositionofAlgorithm("zlib", 1);
		prefCompressionCS = supportedCompressionsCS()
				.changePositionofAlgorithm("zlib@openssh.com", 2);

		supportedCompressionsSC().changePositionofAlgorithm("none", 0);
		supportedCompressionsSC().changePositionofAlgorithm("zlib", 1);
		prefCompressionSC = supportedCompressionsSC()
				.changePositionofAlgorithm("zlib@openssh.com", 2);

	}

	/**
	 * Get this context's supported key exchange methods.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedKeyExchanges() {
		return keyExchanges;
	}

	/**
	 * Get the currently preferred key exchange method.
	 * 
	 * @return the preferred key exhcange
	 */
	public String getPreferredKeyExchange() {
		return prefKeyExchange;
	}

	/**
	 * Set the preferred key exchange method.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredKeyExchange(String name) throws SshException {

		if (name == null)
			return;

		if (keyExchanges.contains(name)) {
			prefKeyExchange = name;
			setKeyExchangePreferredPosition(name, 0);
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Get this context's supported public keys.
	 * 
	 * @return the component factory
	 */
	public ComponentFactory supportedPublicKeys() {
		return publicKeys;
	}

	/**
	 * Get the currently preferred public key algorithm.
	 * 
	 * @return the preferred public key
	 */
	public String getPreferredPublicKey() {
		return prefPublicKey;
	}

	/**
	 * Set the preferred public key algorithm.
	 * 
	 * @param name
	 * @throws SshException
	 */
	public void setPreferredPublicKey(String name) throws SshException {

		if (name == null)
			return;

		if (publicKeys.contains(name)) {
			prefPublicKey = name;
			setPublicKeyPreferredPosition(name, 0);
		} else {
			throw new SshException(name + " is not supported",
					SshException.UNSUPPORTED_ALGORITHM);
		}
	}

	/**
	 * Set the host key verification implementation
	 * 
	 * @param verify
	 */
	public void setHostKeyVerification(HostKeyVerification verify) {
		this.verify = verify;
	}

	/**
	 * Get the host key verification implementation
	 * 
	 * @return HostKeyVerification
	 */
	public HostKeyVerification getHostKeyVerification() {
		return verify;
	}

	public void setSFTPProvider(String sftpProvider) {
		this.sftpProvider = sftpProvider;
	}

	public String getSFTPProvider() {
		return sftpProvider;
	}

	public void setPartialMessageTimeout(int partialMessageTimeout) {
		this.partialMessageTimeout = partialMessageTimeout;
	}

	public int getPartialMessageTimeout() {
		return partialMessageTimeout;
	}

	public boolean isKeyReExchangeDisabled() {
		return keyReExchangeDisabled;
	}

	public void setKeyReExchangeDisabled(boolean keyReExchangeDisabled) {
		this.keyReExchangeDisabled = keyReExchangeDisabled;
	}

	public void setPublicKeyPreferredPosition(String name, int position)
			throws SshException {
		prefPublicKey = publicKeys.changePositionofAlgorithm(name, position);
	}

	public void setKeyExchangePreferredPosition(String name, int position)
			throws SshException {
		prefKeyExchange = keyExchanges
				.changePositionofAlgorithm(name, position);
	}

	public int getIdleConnectionTimeoutSeconds() {
		return idleConnectionTimeoutSeconds;
	}

	public void setIdleConnectionTimeoutSeconds(int idleConnectionTimeoutSeconds) {
		this.idleConnectionTimeoutSeconds = idleConnectionTimeoutSeconds;
	}

	public boolean isDHGroupExchangeBackwardsCompatible() {
		return dhGroupExchangeBackwardCompatible;
	}

	public int getDHGroupExchangeKeySize() {
		return dhGroupExchangeKeySize;
	}

	public void setDHGroupExchangeKeySize(int dhGroupExchangeKeySize) {
		if (dhGroupExchangeKeySize < 1024 || dhGroupExchangeKeySize > 8192) {
			throw new IllegalArgumentException(
					"DH group exchange key size must be between 1024 and 8192");
		}
		this.dhGroupExchangeKeySize = dhGroupExchangeKeySize;
	}

	public void setDHGroupExchangeBackwardsCompatible(
			boolean dhGroupExchangeBackwardCompatible) {
		this.dhGroupExchangeBackwardCompatible = dhGroupExchangeBackwardCompatible;
	}

	public boolean isSendIgnorePacketOnIdle() {
		return sendIgnorePacketOnIdle;
	}

	public void setSendIgnorePacketOnIdle(boolean sendIgnorePacketOnIdle) {
		this.sendIgnorePacketOnIdle = sendIgnorePacketOnIdle;
	}

	public int getKeepAliveMaxDataLength() {
		return keepAliveMaxDataLength;
	}

	public void setKeepAliveMaxDataLength(int keepAliveMaxDataLength) {
		if (keepAliveMaxDataLength < 8)
			throw new IllegalArgumentException(
					"There must be at least 8 bytes of random data");
		this.keepAliveMaxDataLength = keepAliveMaxDataLength;
	}

	public int getSocketTimeout() {
		return socketTimeout;
	}

	public void setSocketTimeout(int socketTimeout) {
		this.socketTimeout = socketTimeout;
	}

	public void enableFIPSMode() throws SshException {

		Log.info(this, "Enabling FIPS mode");

		if (!keyExchanges.contains(Ssh2Context.KEX_DIFFIE_HELLMAN_GROUP14_SHA1)) {
			throw new SshException(
					"Cannot enable FIPS mode because diffie-hellman-group14-sha1 "
							+ "keyexchange was not supported by this configuration. "
							+ "Install a JCE Provider that supports a prime size of 2048 bits (for example BouncyCastle provider)",
					SshException.BAD_API_USAGE);
		}

		if (dhGroupExchangeKeySize < 2048) {
			dhGroupExchangeKeySize = 2048;
		}

		Vector<String> allowed = new Vector<String>();
		allowed.addElement(Ssh2Context.KEX_DIFFIE_HELLMAN_GROUP14_SHA1);
		allowed.addElement(Ssh2Context.KEX_DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1);
		allowed.addElement(Ssh2Context.KEX_DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256);

		String[] names = keyExchanges.toArray();
		for (int i = 0; i < names.length; i++) {
			if (!allowed.contains(names[i])) {
				Log.info(this, "Removing key exchange " + names[i]);
				keyExchanges.remove(names[i]);
			}
		}

		keyExchanges.lockComponents();

		allowed.clear();

		allowed.addElement(Ssh2Context.CIPHER_AES128_CBC);
		allowed.addElement(Ssh2Context.CIPHER_AES192_CBC);
		allowed.addElement(Ssh2Context.CIPHER_AES256_CBC);
		allowed.addElement(Ssh2Context.CIPHER_TRIPLEDES_CBC);

		names = ciphersCS.toArray();
		for (int i = 0; i < names.length; i++) {
			if (!allowed.contains(names[i])) {
				Log.info(this, "Removing cipher client->server "
						+ names[i]);
				ciphersCS.remove(names[i]);
			}
		}

		ciphersCS.lockComponents();

		names = ciphersSC.toArray();
		for (int i = 0; i < names.length; i++) {
			if (!allowed.contains(names[i])) {
				Log.info(this, "Removing cipher server->client "
						+ names[i]);
				ciphersSC.remove(names[i]);
			}
		}

		ciphersSC.lockComponents();

		allowed.clear();

		allowed.addElement(Ssh2Context.PUBLIC_KEY_SSHRSA);

		names = publicKeys.toArray();
		for (int i = 0; i < names.length; i++) {
			if (!allowed.contains(names[i])) {
				Log.info(this, "Removing public key " + names[i]);
				publicKeys.remove(names[i]);
			}
		}

		publicKeys.lockComponents();

		allowed.clear();

		allowed.addElement(Ssh2Context.HMAC_SHA1);
		allowed.addElement(Ssh2Context.HMAC_SHA256);
		allowed.addElement("hmac-sha256@ssh.com");

		names = macCS.toArray();
		for (int i = 0; i < names.length; i++) {
			if (!allowed.contains(names[i])) {
				Log.info(this, "Removing mac client->server "
						+ names[i]);
				macCS.remove(names[i]);
			}
		}

		macCS.lockComponents();

		names = macSC.toArray();
		for (int i = 0; i < names.length; i++) {
			if (!allowed.contains(names[i])) {
				Log.info(this, "Removing mac server->client "
						+ names[i]);
				macSC.remove(names[i]);
			}
		}

		macCS.lockComponents();

	}
}

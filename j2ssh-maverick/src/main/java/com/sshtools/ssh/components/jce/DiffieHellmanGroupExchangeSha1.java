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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.Digest;
import com.sshtools.ssh.components.SshKeyExchangeClient;
import com.sshtools.ssh2.TransportProtocol;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * An implementation of the diffie-hellman-group-exchange key exchange mechanism
 * that uses JCE provider for DH agreement and Digest.
 * 
 * @author Lee David Painter
 */
public class DiffieHellmanGroupExchangeSha1 extends SshKeyExchangeClient
		implements AbstractKeyExchange {

	/**
	 * Constant for the algorithm name "diffie-hellman-group-exchange-sha1".
	 */
	public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = "diffie-hellman-group-exchange-sha1";

	final static int SSH_MSG_KEXDH_GEX_REQUEST_OLD = 30;
	final static int SSH_MSG_KEXDH_GEX_GROUP = 31;
	final static int SSH_MSG_KEXDH_GEX_INIT = 32;
	final static int SSH_MSG_KEXDH_GEX_REPLY = 33;
	final static int SSH_MSG_KEXDH_GEX_REQUEST = 34;

	BigInteger g;
	BigInteger p;
	static BigInteger ONE = BigInteger.valueOf(1);
	BigInteger e = null;
	BigInteger f = null;
	BigInteger y = null;
	String clientId;
	String serverId;
	byte[] clientKexInit;
	byte[] serverKexInit;

	KeyPairGenerator dhKeyPairGen;
	KeyAgreement dhKeyAgreement;
	KeyFactory dhKeyFactory;

	/**
	 * Construct an uninitialized instance.
	 */
	public DiffieHellmanGroupExchangeSha1() {
		this("SHA-1");
	}

	protected DiffieHellmanGroupExchangeSha1(String algorithm) {
		super(algorithm);
	}

	public boolean isKeyExchangeMessage(int messageid) {
		switch (messageid) {
		case SSH_MSG_KEXDH_GEX_REQUEST_OLD:
		case SSH_MSG_KEXDH_GEX_INIT:
		case SSH_MSG_KEXDH_GEX_GROUP:
		case SSH_MSG_KEXDH_GEX_REPLY:
		case SSH_MSG_KEXDH_GEX_REQUEST:
			return true;
		default:
			return false;
		}
	}

	/**
	 * Get the algorithm name for this key exchange
	 * 
	 * @return "diffie-hellman-group1-sha1"
	 */
	public String getAlgorithm() {
		return DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1;
	}

	/**
	 * The client requests a modulus from the server indicating the pre- ferred
	 * size. In the following description (C is the client, S is the server; the
	 * modulus p is a large safe prime and g is a genera- tor for a subgroup of
	 * GF(p); min is the minimal size of p in bits that is acceptable to the
	 * client; n is the size of the modulus p in bits that the client would like
	 * to receive from the server; max is the maximal size of p in bits that the
	 * client can accept; V_S is S's version string; V_C is C's version string;
	 * K_S is S's public host key; I_C is C's KEXINIT message and I_S S's
	 * KEXINIT message which have been exchanged before this part begins):
	 * 
	 * <pre>
	 *  1.   C sends "min || n || max" to S, indicating the minimal accept-
	 *       able group size, the preferred size of the group and the maxi-
	 *       mal group size in bits the client will accept.
	 * 
	 *  2.   S finds a group that best matches the client's request, and
	 *       sends "p || g" to C.
	 * 
	 *  3.   C generates a random number x (1 < x < (p-1)/2). It computes e
	 *       = g^x mod p, and sends "e" to S.
	 * 
	 *  4.   S generates a random number y (0 < y < (p-1)/2) and computes f
	 *       = g^y mod p. S receives "e".  It computes K = e^y mod p, H =
	 *       hash(V_C || V_S || I_C || I_S || K_S || min || n || max || p
	 *       || g || e || f || K) (these elements are encoded according to
	 *       their types; see below), and signature s on H with its private
	 *       host key.  S sends "K_S || f || s" to C.  The signing opera-
	 *       tion may involve a second hashing operation.
	 * 
	 *       Implementation Notes:
	 * 
	 *            To increase the speed of the key exchange, both client
	 *            and server may reduce the size of their private expo-
	 *            nents. It should be at least twice as long as the key
	 *            material that is generated from the shared secret.  For
	 *            more details see the paper by van Oorschot and Wiener
	 *            [1].
	 * 
	 *  5.   C verifies that K_S really is the host key for S (e.g. using
	 *       certificates or a local database).  C is also allowed to
	 *       accept the key without verification; however, doing so will
	 *       render the protocol insecure against active attacks (but may
	 *       be desirable for practical reasons in the short term in many
	 *       environments).  C then computes K = f^x mod p, H = hash(V_C ||
	 *       V_S || I_C || I_S || K_S || min || n || max || p || g || e ||
	 *       f || K), and verifies the signature s on H.
	 * </pre>
	 * 
	 * @param clientIdentification
	 * @param serverIdentification
	 * @param clientKexInit
	 * @param serverKexInit
	 * @throws IOException
	 */
	public void performClientExchange(String clientIdentification,
			String serverIdentification, byte[] clientKexInit,
			byte[] serverKexInit) throws SshException {

		try {
			this.clientId = clientIdentification;
			this.serverId = serverIdentification;
			this.clientKexInit = clientKexInit;
			this.serverKexInit = serverKexInit;

			try {
				dhKeyFactory = JCEProvider
						.getProviderForAlgorithm(JCEAlgorithms.JCE_DH) == null ? KeyFactory
						.getInstance(JCEAlgorithms.JCE_DH) : KeyFactory
						.getInstance(JCEAlgorithms.JCE_DH, JCEProvider
								.getProviderForAlgorithm(JCEAlgorithms.JCE_DH));
				dhKeyPairGen = JCEProvider
						.getProviderForAlgorithm(JCEAlgorithms.JCE_DH) == null ? KeyPairGenerator
						.getInstance(JCEAlgorithms.JCE_DH) : KeyPairGenerator
						.getInstance(JCEAlgorithms.JCE_DH, JCEProvider
								.getProviderForAlgorithm(JCEAlgorithms.JCE_DH));
				dhKeyAgreement = JCEProvider
						.getProviderForAlgorithm(JCEAlgorithms.JCE_DH) == null ? KeyAgreement
						.getInstance(JCEAlgorithms.JCE_DH) : KeyAgreement
						.getInstance(JCEAlgorithms.JCE_DH, JCEProvider
								.getProviderForAlgorithm(JCEAlgorithms.JCE_DH));
			} catch (NoSuchAlgorithmException ex) {
				throw new SshException(
						"JCE does not support Diffie Hellman key exchange",
						SshException.JCE_ERROR);
			}

			ByteArrayWriter msg = new ByteArrayWriter();

			/*
			 * SSH_MSG_KEX_DH_GEX_REQUEST_OLD is used for backwards
			 * compatibility. Instead of sending "min || n || max", the client
			 * only sends "n". Additionally, the hash is calculated using only
			 * "n" instead of "min || n || max".
			 */
			boolean disableBackwardsCompatibility = !transport.getContext()
					.isDHGroupExchangeBackwardsCompatible();
			int preferredKeySize = transport.getContext()
					.getDHGroupExchangeKeySize();

			try {
				msg.write(disableBackwardsCompatibility ? SSH_MSG_KEXDH_GEX_REQUEST
						: SSH_MSG_KEXDH_GEX_REQUEST_OLD);

				if (disableBackwardsCompatibility) {
					// This breaks some old servers, use backwards compatibility
					msg.writeInt(1024);
					msg.writeInt(preferredKeySize);
					msg.writeInt(8192);
				} else {
					msg.writeInt(preferredKeySize);
				}

				transport.sendMessage(msg.toByteArray(), true);

			} finally {
				try {
					msg.close();
				} catch (IOException e) {
				}
			}

			byte[] tmp = transport.nextMessage();

			if (tmp[0] != SSH_MSG_KEXDH_GEX_GROUP) {
				transport.disconnect(TransportProtocol.KEY_EXCHANGE_FAILED,
						"Expected SSH_MSG_KEX_GEX_GROUP");
				throw new SshException(
						"Key exchange failed: Expected SSH_MSG_KEX_GEX_GROUP [id="
								+ tmp[0] + "]", SshException.INTERNAL_ERROR);

			}

			ByteArrayReader bar = new ByteArrayReader(tmp, 1, tmp.length - 1);

			try {

				p = bar.readBigInteger();
				g = bar.readBigInteger();

				DHParameterSpec dhSkipParamSpec = new DHParameterSpec(p, g);
				dhKeyPairGen.initialize(dhSkipParamSpec);

				KeyPair dhKeyPair = dhKeyPairGen.generateKeyPair();
				dhKeyAgreement.init(dhKeyPair.getPrivate());

				e = ((DHPublicKey) dhKeyPair.getPublic()).getY();
			} catch (InvalidKeyException ex) {
				throw new SshException("Failed to generate DH value",
						SshException.JCE_ERROR);
			} catch (InvalidAlgorithmParameterException ex) {
				throw new SshException("Failed to generate DH value",
						SshException.JCE_ERROR);
			} finally {
				try {
					bar.close();
				} catch (IOException e) {
				}
			}

			// Send DH_INIT message
			msg.reset();
			msg.write(SSH_MSG_KEXDH_GEX_INIT);
			msg.writeBigInteger(e);

			transport.sendMessage(msg.toByteArray(), true);

			// Wait for the reply processing any valid transport messages
			tmp = transport.nextMessage();

			if (tmp[0] != SSH_MSG_KEXDH_GEX_REPLY) {
				transport.disconnect(TransportProtocol.KEY_EXCHANGE_FAILED,
						"Expected SSH_MSG_KEXDH_GEX_REPLY");
				throw new SshException(
						"Key exchange failed: Expected SSH_MSG_KEXDH_GEX_REPLY [id="
								+ tmp[0] + "]", SshException.INTERNAL_ERROR);
			}

			bar = new ByteArrayReader(tmp, 1, tmp.length - 1);

			try {
				hostKey = bar.readBinaryString();
				f = bar.readBigInteger();
				signature = bar.readBinaryString();

				// Calculate diffie hellman k value
				DHPublicKeySpec spec = new DHPublicKeySpec(f, p, g);

				DHPublicKey key = (DHPublicKey) dhKeyFactory
						.generatePublic(spec);

				dhKeyAgreement.doPhase(key, true);

				tmp = dhKeyAgreement.generateSecret();
				if ((tmp[0] & 0x80) == 0x80) {
					byte[] tmp2 = new byte[tmp.length + 1];
					System.arraycopy(tmp, 0, tmp2, 1, tmp.length);
					tmp = tmp2;
				}
				// Calculate diffe hellman k value
				secret = new BigInteger(tmp);

				// Calculate the exchange hash
				calculateExchangeHash(disableBackwardsCompatibility,
						preferredKeySize);
			} finally {
				bar.close();
			}
		} catch (Exception ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}

	}

	public String getProvider() {
		if (dhKeyAgreement != null)
			return dhKeyAgreement.getProvider().getName();
		else
			return "";
	}

	/**
	 * <p>
	 * Calculates the exchange hash as an SHA1 hash of the following data.
	 * <blockquote>
	 * 
	 * <pre>
	 *  String         the client's version string (CR and NL excluded)
	 *  String         the server's version string (CR and NL excluded)
	 *  String         the payload of the client's SSH_MSG_KEXINIT
	 *  String         the payload of the server's SSH_MSG_KEXINIT
	 *  String         the host key
	 *  UINT32         minimum size in bits of the acceptable group
	 *  UINT32         preferred size in bits of the acceptable group
	 *  UNIT32         maximum size in bits of the acceptable group
	 *  BigInteger     p, safe prime
	 *  BigInteger     g, generator for subgroup
	 *  BigInteger     e, exchange value sent by the client
	 *  BigInteger     f, exchange value sent by the server
	 *  BigInteger     K, the shared secret
	 * </pre>
	 * 
	 * </blockquote>
	 * </p>
	 * 
	 * @throws IOException
	 */
	protected void calculateExchangeHash(boolean disableBackwardsCompatibility,
			int preferredKeySize) throws SshException {
		Digest hash = (Digest) ComponentManager.getInstance()
				.supportedDigests().getInstance(getHashAlgorithm());

		// The local software version comments
		hash.putString(clientId);

		// The remote software version comments
		hash.putString(serverId);

		// The local kex init payload
		hash.putInt(clientKexInit.length);
		hash.putBytes(clientKexInit);

		// The remote kex init payload
		hash.putInt(serverKexInit.length);
		hash.putBytes(serverKexInit);

		// The host key
		hash.putInt(hostKey.length);
		hash.putBytes(hostKey);

		// Maximum size in bits of the acceptable group
		if (disableBackwardsCompatibility) {
			hash.putInt(1024);
			hash.putInt(preferredKeySize);
			hash.putInt(8192); // This breaks some old servers, use backwards
								// compatibility
		} else {
			hash.putInt(preferredKeySize);
		}

		// The safe prime
		hash.putBigInteger(p);

		// The generator
		hash.putBigInteger(g);

		// The diffie hellman e value
		hash.putBigInteger(e);

		// The diffie hellman f value
		hash.putBigInteger(f);

		// The diffie hellman k value
		hash.putBigInteger(secret);

		// Do the final output
		exchangeHash = hash.doFinal();
	}
}

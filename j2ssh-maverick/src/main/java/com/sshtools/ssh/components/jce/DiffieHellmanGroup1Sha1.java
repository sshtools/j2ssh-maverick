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
import com.sshtools.ssh.components.DiffieHellmanGroups;
import com.sshtools.ssh.components.Digest;
import com.sshtools.ssh.components.SshKeyExchangeClient;
import com.sshtools.ssh2.TransportProtocol;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * An implementation of the diffie-hellman-group1-sha1 key exchange mechanism
 * that uses JCE provider for DH agreement and Digest.
 * 
 * @author Lee David Painter
 */
public class DiffieHellmanGroup1Sha1 extends SshKeyExchangeClient implements
		AbstractKeyExchange {

	/** Constant for the algorithm name "diffie-hellman-group1-sha1". */
	public static final String DIFFIE_HELLMAN_GROUP1_SHA1 = "diffie-hellman-group1-sha1";

	final static int SSH_MSG_KEXDH_INIT = 30;
	final static int SSH_MSG_KEXDH_REPLY = 31;

	final static BigInteger ONE = BigInteger.valueOf(1);
	final static BigInteger TWO = BigInteger.valueOf(2);

	/** generator, RFC recommends using 2 */
	final static BigInteger g = TWO;

	/** large safe prime, this comes from ....?? */
	final static BigInteger p = DiffieHellmanGroups.group1;

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
	public DiffieHellmanGroup1Sha1() {
		super("SHA-1");
	}

	/**
	 * Get the algorithm name for this key exchange
	 * 
	 * @return "diffie-hellman-group1-sha1"
	 */
	public String getAlgorithm() {
		return DIFFIE_HELLMAN_GROUP1_SHA1;
	}

	public String getProvider() {
		if (dhKeyAgreement != null)
			return dhKeyAgreement.getProvider().getName();
		else
			return "";
	}

	public void performClientExchange(String clientIdentification,
			String serverIdentification, byte[] clientKexInit,
			byte[] serverKexInit) throws com.sshtools.ssh.SshException {

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

		KeyPair dhKeyPair = null;
		int retry = 3;
		
		do {
			if(retry==0) {
				transport.disconnect(TransportProtocol.KEY_EXCHANGE_FAILED,
						"Failed to generate key exchange value");
				throw new SshException(
						"Key exchange failed to generate e value",
						SshException.INTERNAL_ERROR);
			}
			
			retry--;
			
			try {

				dhKeyPairGen = JCEProvider
						.getProviderForAlgorithm(JCEAlgorithms.JCE_DH) == null ? KeyPairGenerator
						.getInstance(JCEAlgorithms.JCE_DH) : KeyPairGenerator
						.getInstance(JCEAlgorithms.JCE_DH, JCEProvider
								.getProviderForAlgorithm(JCEAlgorithms.JCE_DH));
						
				DHParameterSpec dhSkipParamSpec = new DHParameterSpec(p, g);
				dhKeyPairGen.initialize(dhSkipParamSpec);

				dhKeyPair = dhKeyPairGen.generateKeyPair();
				
				e = ((DHPublicKey) dhKeyPair.getPublic()).getY();

			} catch (InvalidAlgorithmParameterException ex) {
				throw new SshException("Failed to generate DH value",
						SshException.JCE_ERROR);
			} catch (NoSuchAlgorithmException e1) {
				throw new SshException(
						"JCE does not support Diffie Hellman key exchange",
						SshException.JCE_ERROR);
			}
		} while (e.compareTo(ONE) < 0 || e.compareTo(p.subtract(ONE)) > 0);

		
		ByteArrayWriter msg = new ByteArrayWriter();
		try {
			
			dhKeyAgreement.init(dhKeyPair.getPrivate());
			
			// Send DH_INIT message
			
			msg.write(SSH_MSG_KEXDH_INIT);
			msg.writeBigInteger(e);

			transport.sendMessage(msg.toByteArray(), true);
		} catch (IOException ex) {
			throw new SshException(
					"Failed to write SSH_MSG_KEXDH_INIT to message buffer",
					SshException.INTERNAL_ERROR);
		} catch (InvalidKeyException e1) {
			throw new SshException(
					"JCE reported Diffie Hellman invalid key",
					SshException.JCE_ERROR);
		} finally {
			try {
				msg.close();
			} catch (IOException e) {
			}
		}

		// Wait for the reply processing any valid transport messages
		byte[] tmp;

		tmp = transport.nextMessage();

		if (tmp[0] != SSH_MSG_KEXDH_REPLY) {
			transport.disconnect(TransportProtocol.KEY_EXCHANGE_FAILED,
					"Key exchange failed [id=" + tmp[0] + "]");
			throw new SshException("Key exchange failed [id=" + tmp[0] + "]",
					SshException.INTERNAL_ERROR);
		}

		ByteArrayReader bar = new ByteArrayReader(tmp, 1, tmp.length - 1);

		try {
			hostKey = bar.readBinaryString();
			f = bar.readBigInteger();
			signature = bar.readBinaryString();

			DHPublicKeySpec spec = new DHPublicKeySpec(f, p, g);

			dhKeyAgreement.doPhase(dhKeyFactory.generatePublic(spec), true);

			tmp = dhKeyAgreement.generateSecret();
			if ((tmp[0] & 0x80) == 0x80) {
				byte[] tmp2 = new byte[tmp.length + 1];
				System.arraycopy(tmp, 0, tmp2, 1, tmp.length);
				tmp = tmp2;
			}
			// Calculate diffe hellman k value
			secret = new BigInteger(tmp);

			// Calculate the exchange hash
			calculateExchangeHash();
		} catch (Exception ex) {
			throw new SshException(
					"Failed to read SSH_MSG_KEXDH_REPLY from message buffer",
					SshException.INTERNAL_ERROR, ex);
		} finally {
	    	  try {
	  			bar.close();
	  		} catch (IOException e) {
	  		}
	    }
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
	protected void calculateExchangeHash() throws SshException {

		Digest hash = (Digest) ComponentManager.getInstance()
				.supportedDigests().getInstance("SHA-1");

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

		// The diffie hellman e value
		hash.putBigInteger(e);

		// The diffie hellman f value
		hash.putBigInteger(f);

		// The diffie hellman k value
		hash.putBigInteger(secret);

		// Do the final output
		exchangeHash = hash.doFinal();
	}

	public boolean isKeyExchangeMessage(int messageid) {
		switch (messageid) {
		case SSH_MSG_KEXDH_INIT:
		case SSH_MSG_KEXDH_REPLY:
			return true;
		default:
			return false;
		}
	}

}

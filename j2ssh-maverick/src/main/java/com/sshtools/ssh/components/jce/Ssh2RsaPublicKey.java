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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshKeyFingerprint;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.ssh.components.SshRsaPublicKey;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * A RSA public key implementation which uses a JCE provider.
 * 
 * @author Lee David Painter
 */
public class Ssh2RsaPublicKey implements SshRsaPublicKey {

	RSAPublicKey pubKey;

	/**
	 * Default constructor for initializing the key from a byte array using the
	 * init method.
	 * 
	 */
	public Ssh2RsaPublicKey() {
	}

	public Ssh2RsaPublicKey(RSAPublicKey pubKey) {
		this.pubKey = pubKey;
	}

	public Ssh2RsaPublicKey(BigInteger modulus, BigInteger publicExponent)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = JCEProvider
				.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA) == null ? KeyFactory
				.getInstance(JCEAlgorithms.JCE_RSA) : KeyFactory.getInstance(
				JCEAlgorithms.JCE_RSA,
				JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA));
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
		pubKey = (RSAPublicKey) keyFactory.generatePublic(spec);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.sshtools.ssh.publickey.RsaPublicKey#getEncoded()
	 */
	public byte[] getEncoded() throws SshException {
		ByteArrayWriter baw = new ByteArrayWriter();
		try {

			baw.writeString(getAlgorithm());
			baw.writeBigInteger(pubKey.getPublicExponent());
			baw.writeBigInteger(pubKey.getModulus());

			return baw.toByteArray();
		} catch (IOException ex) {
			throw new SshException("Failed to encoded key data",
					SshException.INTERNAL_ERROR, ex);
		} finally {
			try {
				baw.close();
			} catch (IOException e) {
			}
		}
	}

	public String getFingerprint() throws SshException {
		return SshKeyFingerprint.getFingerprint(getEncoded());
	}

	public int getBitLength() {
		return pubKey.getModulus().bitLength();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.sshtools.ssh.SshPublicKey#init(byte[], int, int)
	 */
	public void init(byte[] blob, int start, int len) throws SshException {

		ByteArrayReader bar = new ByteArrayReader(blob, start, len);

		try {
			// this.hostKey = hostKey;
			RSAPublicKeySpec rsaKey;

			// Extract the key information
			String header = bar.readString();

			if (!header.equals(getAlgorithm())) {
				throw new SshException("The encoded key is not RSA",
						SshException.INTERNAL_ERROR);
			}

			BigInteger e = bar.readBigInteger();
			BigInteger n = bar.readBigInteger();
			rsaKey = new RSAPublicKeySpec(n, e);

			try {
				KeyFactory kf = JCEProvider
						.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA) == null ? KeyFactory
						.getInstance(JCEAlgorithms.JCE_RSA)
						: KeyFactory
								.getInstance(
										JCEAlgorithms.JCE_RSA,
										JCEProvider
												.getProviderForAlgorithm(JCEAlgorithms.JCE_RSA));
				pubKey = (RSAPublicKey) kf.generatePublic(rsaKey);

			} catch (Exception ex) {
				throw new SshException(
						"Failed to obtain RSA key instance from JCE",
						SshException.INTERNAL_ERROR, ex);
			}
		} catch (IOException ioe) {
			throw new SshException("Failed to read encoded key data",
					SshException.INTERNAL_ERROR);
		} finally {
			try {
				bar.close();
			} catch (IOException e) {
			}
		}

	}

	public String getAlgorithm() {
		return "ssh-rsa";
	}

	public boolean verifySignature(byte[] signature, byte[] data)
			throws SshException {
		ByteArrayReader bar = new ByteArrayReader(signature);
		try {
			// Check for older versions of the transport protocol
			if (signature.length != 128) {
				byte[] sig = bar.readBinaryString();
				@SuppressWarnings("unused")
				String header = new String(sig);
				signature = bar.readBinaryString();
			}

			Signature s;

			s = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithRSA) == null ? Signature
					.getInstance(JCEAlgorithms.JCE_SHA1WithRSA)
					: Signature
							.getInstance(
									JCEAlgorithms.JCE_SHA1WithRSA,
									JCEProvider
											.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithRSA));
			s.initVerify(pubKey);
			s.update(data);

			return s.verify(signature);

		} catch (Exception ex) {
			throw new SshException(SshException.JCE_ERROR, ex);
		} finally {
			try {
				bar.close();
			} catch (IOException e) {
			}
		}

	}

	public boolean equals(Object obj) {
		if (obj instanceof SshRsaPublicKey) {
			try {
				return (((SshPublicKey) obj).getFingerprint()
						.equals(getFingerprint()));
			} catch (SshException ex) {
			}
		}

		return false;
	}

	public int hashCode() {
		try {
			return getFingerprint().hashCode();
		} catch (SshException ex) {
			return 0;
		}
	}

	public BigInteger doPublic(BigInteger input) throws SshException {
		try {

			Cipher cipher = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_RSANONEPKCS1PADDING) == null ? Cipher
					.getInstance(JCEAlgorithms.JCE_RSANONEPKCS1PADDING)
					: Cipher.getInstance(
							JCEAlgorithms.JCE_RSANONEPKCS1PADDING,
							JCEProvider
									.getProviderForAlgorithm(JCEAlgorithms.JCE_RSANONEPKCS1PADDING));
			cipher.init(Cipher.ENCRYPT_MODE, pubKey,
					JCEProvider.getSecureRandom());
			byte[] tmp = input.toByteArray();
			return new BigInteger(cipher.doFinal(tmp, tmp[0] == 0 ? 1 : 0,
					tmp[0] == 0 ? tmp.length - 1 : tmp.length));

		} catch (Throwable e) {
			if (e.getMessage().indexOf(JCEAlgorithms.JCE_RSANONEPKCS1PADDING) > -1)
				throw new SshException(
						"JCE provider requires BouncyCastle provider for RSA/NONE/PKCS1Padding component. Add bcprov.jar to your classpath or configure an alternative provider for this algorithm",
						SshException.INTERNAL_ERROR);
			throw new SshException(e);
		}
	}

	public BigInteger getModulus() {
		return pubKey.getModulus();
	}

	public BigInteger getPublicExponent() {
		return pubKey.getPublicExponent();
	}

	public int getVersion() {
		return 2;
	}
}

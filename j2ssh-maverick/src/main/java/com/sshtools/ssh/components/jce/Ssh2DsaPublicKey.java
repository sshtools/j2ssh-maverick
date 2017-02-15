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
package com.sshtools.ssh.components.jce;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshKeyFingerprint;
import com.sshtools.ssh.components.SshDsaPublicKey;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;
import com.sshtools.util.SimpleASNWriter;

/**
 * A DSA public key implementation which uses a JCE provider.
 * 
 * @author Lee David Painter
 */
public class Ssh2DsaPublicKey implements SshDsaPublicKey {

	protected DSAPublicKey pubkey;

	public Ssh2DsaPublicKey() {
	}

	public Ssh2DsaPublicKey(DSAPublicKey pub) {
		this.pubkey = pub;
	}

	public Ssh2DsaPublicKey(BigInteger p, BigInteger q, BigInteger g,
			BigInteger y) throws NoSuchAlgorithmException,
			InvalidKeySpecException {

		KeyFactory keyFactory = JCEProvider
				.getProviderForAlgorithm(JCEAlgorithms.JCE_DSA) == null ? KeyFactory
				.getInstance(JCEAlgorithms.JCE_DSA) : KeyFactory.getInstance(
				JCEAlgorithms.JCE_DSA,
				JCEProvider.getProviderForAlgorithm(JCEAlgorithms.JCE_DSA));
		KeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
		pubkey = (DSAPublicKey) keyFactory.generatePublic(publicKeySpec);
	}

	/**
	 * Get the algorithm name for the public key.
	 * 
	 * @return the algorithm name, for example "ssh-dss"
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public String getAlgorithm() {
		return "ssh-dss";
	}

	/**
	 * 
	 * @return the bit length of the public key
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public int getBitLength() {
		return pubkey.getParams().getP().bitLength();
	}

	/**
	 * Encode the public key into a blob of binary data, the encoded result will
	 * be passed into init to recreate the key.
	 * 
	 * @return an encoded byte array
	 * @throws SshException
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public byte[] getEncoded() throws SshException {
		ByteArrayWriter baw = new ByteArrayWriter();
		try {

			baw.writeString(getAlgorithm());
			baw.writeBigInteger(pubkey.getParams().getP());
			baw.writeBigInteger(pubkey.getParams().getQ());
			baw.writeBigInteger(pubkey.getParams().getG());
			baw.writeBigInteger(pubkey.getY());

			return baw.toByteArray();
		} catch (IOException ioe) {
			throw new SshException("Failed to encoded DSA key",
					SshException.INTERNAL_ERROR, ioe);
		} finally {
			try {
				baw.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * 
	 * @return java.lang.String
	 * @throws SshException
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public String getFingerprint() throws SshException {
		return SshKeyFingerprint.getFingerprint(getEncoded());
	}

	/**
	 * Initialize the public key from a blob of binary data.
	 * 
	 * @param blob
	 *            byte[]
	 * @param start
	 *            int
	 * @param len
	 *            int
	 * @throws SshException
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public void init(byte[] blob, int start, int len) throws SshException {

		ByteArrayReader bar = new ByteArrayReader(blob, start, len);

		try {
			DSAPublicKeySpec dsaKey;

			// Extract the key information
			String header = bar.readString();

			if (!header.equals(getAlgorithm())) {
				throw new SshException("The encoded key is not DSA",
						SshException.INTERNAL_ERROR);
			}

			BigInteger p = bar.readBigInteger();
			BigInteger q = bar.readBigInteger();
			BigInteger g = bar.readBigInteger();
			BigInteger y = bar.readBigInteger();
			dsaKey = new DSAPublicKeySpec(y, p, q, g);

			KeyFactory kf = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_DSA) == null ? KeyFactory
					.getInstance(JCEAlgorithms.JCE_DSA) : KeyFactory
					.getInstance(JCEAlgorithms.JCE_DSA, JCEProvider
							.getProviderForAlgorithm(JCEAlgorithms.JCE_DSA));
			pubkey = (DSAPublicKey) kf.generatePublic(dsaKey);

		} catch (Exception ex) {
			throw new SshException(
					"Failed to obtain DSA key instance from JCE",
					SshException.INTERNAL_ERROR, ex);

		} finally {
			try {
				bar.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * Verify the signature.
	 * 
	 * @param signature
	 *            byte[]
	 * @param data
	 *            byte[]
	 * @return <code>true</code> if the signature was produced by the
	 *         corresponding private key that owns this public key, otherwise
	 *         <code>false</code>.
	 * @throws SshException
	 * @todo Implement this com.sshtools.ssh.SshPublicKey method
	 */
	public boolean verifySignature(byte[] signature, byte[] data)
			throws SshException {

		ByteArrayReader bar = new ByteArrayReader(signature);

		try {

			if (signature.length != 40 // 160 bits
					&& signature.length != 56 // 224 bits
					&& signature.length != 64) { // 256 bits

				byte[] sig = bar.readBinaryString();

				// log.debug("Signature blob is " + new String(sig));
				String header = new String(sig);

				if (!header.equals("ssh-dss")) {
					throw new SshException("The encoded signature is not DSA",
							SshException.INTERNAL_ERROR);
				}

				signature = bar.readBinaryString();
			}

			int numSize = signature.length / 2;

			// Using a SimpleASNWriter
			ByteArrayOutputStream r = new ByteArrayOutputStream();
			ByteArrayOutputStream s = new ByteArrayOutputStream();
			SimpleASNWriter asn = new SimpleASNWriter();
			asn.writeByte(0x02);

			if (((signature[0] & 0x80) == 0x80) && (signature[0] != 0x00)) {
				r.write(0);
				r.write(signature, 0, numSize);
			} else {
				r.write(signature, 0, numSize);
			}

			asn.writeData(r.toByteArray());
			asn.writeByte(0x02);

			if (((signature[numSize] & 0x80) == 0x80)
					&& (signature[numSize] != 0x00)) {
				s.write(0);
				s.write(signature, numSize, numSize);
			} else {
				s.write(signature, numSize, numSize);
			}

			asn.writeData(s.toByteArray());

			SimpleASNWriter asnEncoded = new SimpleASNWriter();
			asnEncoded.writeByte(0x30);
			asnEncoded.writeData(asn.toByteArray());

			byte[] encoded = asnEncoded.toByteArray();

			Signature sig = JCEProvider
					.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithDSA) == null ? Signature
					.getInstance(JCEAlgorithms.JCE_SHA1WithDSA)
					: Signature
							.getInstance(
									JCEAlgorithms.JCE_SHA1WithDSA,
									JCEProvider
											.getProviderForAlgorithm(JCEAlgorithms.JCE_SHA1WithDSA));
			sig.initVerify(pubkey);
			sig.update(data);

			return sig.verify(encoded);
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
		if (obj instanceof SshDsaPublicKey) {
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

	public BigInteger getG() {
		return pubkey.getParams().getG();
	}

	public BigInteger getP() {
		return pubkey.getParams().getP();
	}

	public BigInteger getQ() {
		return pubkey.getParams().getQ();
	}

	public BigInteger getY() {
		return pubkey.getY();
	}
}

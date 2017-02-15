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
package com.sshtools.ssh;

import com.sshtools.ssh.components.ComponentManager;
import com.sshtools.ssh.components.Digest;

/**
 * Utility methods to generate an SSH public key fingerprint.
 * 
 * @author Lee David Painter
 */
public class SshKeyFingerprint {

	public final static String MD5_FINGERPRINT = "MD5";
	public final static String SHA1_FINGERPRINT = "SHA-1";
	public final static String SHA256_FINGERPRINT = "SHA-256";

	private static String defaultHashAlgoritm = MD5_FINGERPRINT;

	static char[] HEX = new char[] { '0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	/**
	 * Generate an SSH key fingerprint as defined in
	 * draft-ietf-secsh-fingerprint-00.txt.
	 * 
	 * @param encoded
	 * @return the key fingerprint, for example
	 *         "c1:b1:30:29:d7:b8:de:6c:97:77:10:d7:46:41:63:87"
	 */
	public static String getFingerprint(byte[] encoded) throws SshException {
		return getFingerprint(encoded, defaultHashAlgoritm);
	}

	public static void setDefaultHashAlgorithm(String defaultHashAlgorithm) {
		SshKeyFingerprint.defaultHashAlgoritm = defaultHashAlgorithm;
	}

	/**
	 * Generate an SSH key fingerprint with a specific algorithm.
	 * 
	 * @param encoded
	 * @param algorithm
	 * @return the key fingerprint, for example
	 *         "c1:b1:30:29:d7:b8:de:6c:97:77:10:d7:46:41:63:87"
	 */
	public static String getFingerprint(byte[] encoded, String algorithm)
			throws SshException {

		Digest md5 = (Digest) ComponentManager.getInstance().supportedDigests()
				.getInstance(algorithm);

		md5.putBytes(encoded);

		byte[] digest = md5.doFinal();

		StringBuffer buf = new StringBuffer();
		int ch;
		for (int i = 0; i < digest.length; i++) {
			ch = digest[i] & 0xFF;
			if (i > 0) {
				buf.append(':');
			}
			buf.append(HEX[(ch >>> 4) & 0x0F]);
			buf.append(HEX[ch & 0x0F]);
		}

		return buf.toString();
	}
}

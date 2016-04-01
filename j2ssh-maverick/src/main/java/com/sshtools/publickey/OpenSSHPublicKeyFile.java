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
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.publickey;

import java.io.IOException;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.util.Base64;

public class OpenSSHPublicKeyFile implements SshPublicKeyFile {

	byte[] formattedkey;
	String comment;

	OpenSSHPublicKeyFile(byte[] formattedkey) throws IOException {
		this.formattedkey = formattedkey;
		toPublicKey(); // To validate
	}

	OpenSSHPublicKeyFile(SshPublicKey key, String comment) throws IOException {

		try {
			String formatted = key.getAlgorithm() + " "
					+ Base64.encodeBytes(key.getEncoded(), true);

			if (comment != null) {
				formatted += (" " + comment);
			}

			formattedkey = formatted.getBytes();
		} catch (SshException ex) {
			throw new IOException("Failed to encode public key");
		}
	}

	public String toString() {
		return new String(formattedkey);
	}

	public byte[] getFormattedKey() {
		return formattedkey;
	}

	public SshPublicKey toPublicKey() throws IOException {

		String temp = new String(formattedkey);

		// Get the algorithm name end index
		int i = temp.indexOf(" ");

		if (i > 0) {
			String algorithm = temp.substring(0, i);

			// Get the keyblob end index
			int i2 = temp.indexOf(" ", i + 1);

			String encoded;
			if (i2 != -1) {
				encoded = temp.substring(i + 1, i2);

				if (temp.length() > i2) {
					comment = temp.substring(i2 + 1).trim();
				}

				return SshPublicKeyFileFactory.decodeSSH2PublicKey(algorithm,
						Base64.decode(encoded));

			}
			encoded = temp.substring(i + 1);
			return SshPublicKeyFileFactory.decodeSSH2PublicKey(algorithm,
					Base64.decode(encoded));
		}

		throw new IOException("Key format not supported!");
	}

	public String getComment() {
		return comment;
	}

}

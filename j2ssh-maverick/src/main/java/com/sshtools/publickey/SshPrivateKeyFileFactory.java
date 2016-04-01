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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.sshtools.ssh.components.SshKeyPair;

/**
 * Private key format factory used to decode private key files. This factory
 * currently supports SSHTools, OpenSSH and SSH1 encrypted private keys.
 * 
 * @author Lee David Painter
 */
public class SshPrivateKeyFileFactory {

	public static final int OPENSSH_FORMAT = 0;
	public static final int SSHTOOLS_FORMAT = 1;

	/**
	 * Parse formatted data and return a suitable <a
	 * href="SshPrivateKeyFile.html">SshPrivateKeyFile</a> implementation.
	 * 
	 * @param formattedkey
	 * @return SshPrivateKeyFile
	 * @throws IOException
	 */
	public static SshPrivateKeyFile parse(byte[] formattedkey)
			throws IOException {

		try {
			if (OpenSSHPrivateKeyFile.isFormatted(formattedkey)) {
				return new OpenSSHPrivateKeyFile(formattedkey);
			} else if (Base64EncodedFileFormat.isFormatted(formattedkey,
					SshtoolsPrivateKeyFile.BEGIN, SshtoolsPrivateKeyFile.END)) {
				return new SshtoolsPrivateKeyFile(formattedkey);
			} else if (PuTTYPrivateKeyFile.isFormatted(formattedkey)) {
				return new PuTTYPrivateKeyFile(formattedkey);
			} else if (SSHCOMPrivateKeyFile.isFormatted(formattedkey)) {
				return new SSHCOMPrivateKeyFile(formattedkey);
			} else {
				throw new IOException(
						"A suitable key format could not be found!");
			}
		} catch (OutOfMemoryError ex) {
			throw new IOException(
					"An error occurred parsing a private key file! Is the file corrupt?");
		}

	}

	/**
	 * Parse an InputStream and return a suitable <a
	 * href="SshPrivateKeyFile.html">SshPrivateKeyFile</a> implementation.
	 * 
	 * @param in
	 * @return SshPrivateKeyFile
	 * @throws IOException
	 */
	public static SshPrivateKeyFile parse(InputStream in) throws IOException {

		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int read;
			while ((read = in.read()) > -1) {
				out.write(read);
			}
			return parse(out.toByteArray());
		} finally {
			try {
				in.close();
			} catch (IOException ex) {
			}
		}

	}

	public static SshPrivateKeyFile create(SshKeyPair pair, String passphrase,
			String comment, int format) throws IOException {

		switch (format) {
		case OPENSSH_FORMAT:
			return new OpenSSHPrivateKeyFile(pair, passphrase);
		case SSHTOOLS_FORMAT:
			return new SshtoolsPrivateKeyFile(pair, passphrase, comment);
		default:
			throw new IOException("Invalid key format!");
		}

	}

	/**
	 * Take a <a href="SshPrivateKey.html">SshPrivateKey</a> and write it to a
	 * file.
	 * 
	 * @param key
	 * @param comment
	 * @param format
	 * @param toFile
	 * @throws IOException
	 */
	public static void createFile(SshKeyPair key, String passphrase,
			String comment, int format, File toFile) throws IOException {

		SshPrivateKeyFile pub = create(key, passphrase, comment, format);

		FileOutputStream out = new FileOutputStream(toFile);

		try {
			out.write(pub.getFormattedKey());
			out.flush();
		} finally {
			out.close();
		}
	}

	/**
	 * Take a file in any of the supported public key formats and convert to the
	 * requested format.
	 * 
	 * @param keyFile
	 * @param toFormat
	 * @param toFile
	 * @throws IOException
	 * @throws InvalidPassphraseException
	 */
	public static void convertFile(File keyFile, String passphrase,
			String comment, int toFormat, File toFile) throws IOException,
			InvalidPassphraseException {

		SshPrivateKeyFile pub = parse(new FileInputStream(keyFile));

		createFile(pub.toKeyPair(passphrase), passphrase, comment, toFormat,
				toFile);
	}
}

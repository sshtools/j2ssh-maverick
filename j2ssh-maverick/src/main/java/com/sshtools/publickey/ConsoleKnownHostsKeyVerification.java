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

package com.sshtools.publickey;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshKeyFingerprint;
import com.sshtools.ssh.components.SshPublicKey;

/**
 * <p>
 * Implements the <a href="AbstractKnownHostsKeyVerification.html">
 * AbstractKnownHostsKeyVerification</a> to provide host key verification
 * through the console.
 * </p>
 * 
 * @author Lee David Painter
 */
public class ConsoleKnownHostsKeyVerification extends
		AbstractKnownHostsKeyVerification {
	/**
	 * <p>
	 * Constructs the verification instance with the default known_hosts file
	 * from $HOME/.ssh/known_hosts.
	 * </p>
	 * 
	 * @throws InvalidHostFileException
	 *             if the known_hosts file is invalid.
	 * 
	 * @since 0.2.0
	 */
	public ConsoleKnownHostsKeyVerification() throws SshException {
		super();
	}

	/**
	 * <p>
	 * Constructs the verification instance with the specified known_hosts file.
	 * </p>
	 * 
	 * @param knownhosts
	 *            the path to the known_hosts file
	 * 
	 * @throws InvalidHostFileException
	 *             if the known_hosts file is invalid.
	 * 
	 * @since 0.2.0
	 */
	public ConsoleKnownHostsKeyVerification(String knownhosts)
			throws SshException {
		super(knownhosts);
	}

	/**
	 * <p>
	 * Prompts the user through the console to verify the host key.
	 * </p>
	 * 
	 * @param host
	 *            the name of the host
	 * @param pk
	 *            the current public key of the host
	 * @param actual
	 *            the actual public key supplied by the host
	 * 
	 * @since 0.2.0
	 */
	public void onHostKeyMismatch(String host, SshPublicKey pk,
			SshPublicKey actual) {
		try {
			System.out.println("The host key supplied by " + host + "("
					+ pk.getAlgorithm() + ")" + " is: "
					+ actual.getFingerprint());
			System.out.println("The current allowed key for " + host + " is: "
					+ pk.getFingerprint());
			getResponse(host, actual);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * <p>
	 * Prompts the user through the console to verify the host key.
	 * </p>
	 * 
	 * @param host
	 *            the name of the host
	 * @param pk
	 *            the public key supplied by the host
	 * 
	 * @since 0.2.0
	 */
	public void onUnknownHost(String host, SshPublicKey pk) {
		try {
			System.out.println("The host " + host
					+ " is currently unknown to the system");
			System.out.println("The MD5 host key " + "(" + pk.getAlgorithm()
					+ ") fingerprint is: " + pk.getFingerprint());
			System.out.println("The SHA1 host key "
					+ "("
					+ pk.getAlgorithm()
					+ ") fingerprint is: "
					+ SshKeyFingerprint.getFingerprint(pk.getEncoded(),
							SshKeyFingerprint.SHA1_FINGERPRINT));
			try {
				System.out.println("The SHA256 host key "
						+ "("
						+ pk.getAlgorithm()
						+ ") fingerprint is: "
						+ SshKeyFingerprint.getFingerprint(pk.getEncoded(),
								SshKeyFingerprint.SHA256_FINGERPRINT));
			} catch (Exception ex) {
			}

			getResponse(host, pk);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void onInvalidHostEntry(String entry) throws SshException {
		System.out.println("Invalid host entry in "
				+ getKnownHostsFile().getAbsolutePath());
		System.out.println(entry);
	}

	private void getResponse(String host, SshPublicKey pk) throws SshException {
		String response = "";
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				System.in));

		while (!(response.equalsIgnoreCase("YES")
				|| response.equalsIgnoreCase("NO") || (response
				.equalsIgnoreCase("ALWAYS") && isHostFileWriteable()))) {
			String options = (isHostFileWriteable() ? "Yes|No|Always"
					: "Yes|No");

			if (!isHostFileWriteable()) {
				System.out
						.println("Always option disabled, host file is not writeable");
			}

			System.out.print("Do you want to allow this host key? [" + options
					+ "]: ");

			try {
				response = reader.readLine();
			} catch (IOException ex) {
				throw new SshException("Failed to read response",
						SshException.INTERNAL_ERROR);
			}
		}

		if (response.equalsIgnoreCase("YES")) {
			allowHost(host, pk, false);
		}

		if (response.equalsIgnoreCase("ALWAYS") && isHostFileWriteable()) {
			allowHost(host, pk, true);
		}

		// Do nothing on NO
	}
}

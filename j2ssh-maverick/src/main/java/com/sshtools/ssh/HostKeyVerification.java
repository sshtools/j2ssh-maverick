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

package com.sshtools.ssh;

import com.sshtools.ssh.components.SshPublicKey;

/**
 * <p>
 * This interface provides a callback method so that the user can verify the
 * identity of the server (by checking the public key) during the initial
 * protocol negotiation. This check is performed at the beginning of each
 * connection to prevent trojan horses (by routing or DNS spoofing) and
 * man-in-the-middle attacks.
 * </p>
 * <p>
 * The user should verify that the key is acceptable; the most usual method
 * being a local database file called <em>known_hosts</em>. The core J2SSH
 * Maverick engine does not enforce any specific host key verification in order
 * that the engine can be used on Java platforms that do not have File objects.
 * A <em>known_hosts</em> implementation <a
 * href="../../sshtools/publickey/AbstractKnownHostsKeyVerification.html"
 * >AbstractKnownHostsKeyVerification</a> can be found in the SSHTools utility
 * classes supplied with the J2SSH Maverick API. This also includes the basic <a
 * href="../../sshtools/publickey/ConsoleKnownHostsKeyVerification.html">
 * ConsoleKnownHostsKeyVerification</a> which performs the check by prompting
 * the user through stdin/stdout.
 * </p>
 * <p>
 * The public key instances supplied to the <a href=
 * "#verifyHost(java.lang.String, com.maverick.ssh.components.SshPublicKey)">
 * verifyHost</a> method will be one of the following implementations:<br>
 * </p>
 * <p>
 * To set a host key verification you must get an instance of the SshConnector
 * and configure the SSH version context's with your implementation.
 * <blockquote>
 * 
 * <pre>
 * SshConnector con = SshConnector.getInstance();
 * 
 * HostKeyVerification hkv = new HostKeyVerification() {
 * 	public boolean verifyHost(String name, SshPublicKey key) throws IOException {
 * 		// Verify the host somehow???
 * 		return true;
 * 	}
 * };
 * SshContext context = con.getContext();
 * context.setHostKeyVerification(hkv);
 * </pre>
 * 
 * </blockquote>
 * </p>
 * 
 * @author Lee David Painter
 */
public interface HostKeyVerification {

	/**
	 * Verify that the public key is acceptable for the host.
	 * 
	 * @param host
	 *            the name of the connected host
	 * @param pk
	 *            the public key supplied by the host
	 * @return <code>true</code> if the host key is acceptable otherwise
	 *         <code>false</code>
	 * @throws SshException
	 */
	public boolean verifyHost(String host, SshPublicKey pk) throws SshException;
}

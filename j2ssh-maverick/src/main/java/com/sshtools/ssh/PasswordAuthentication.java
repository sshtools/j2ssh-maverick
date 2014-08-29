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

/**
 * <p>
 * Basic password authentication class used for SSH password authentication.
 * Once a connection has been established to an SSH server the user is normally
 * required to authenticate themselves. This class implements a basic password
 * <a href="SshAuthentication.html">SshAuthentication</a> that can be passed
 * into the <a href="SshClient.html">SshClient</a> to authenticate. As a
 * username is required to establish a connection it is not required that it be
 * set on the password object, however if you wish to change the username you
 * can do so (this may not be allowed by some server implementations).
 * </p>
 * 
 * <p>
 * Use password authentication as follows: <blockquote>
 * 
 * <pre>
 * SshConnector con = SshConnector.getInstance();
 * SshClient ssh = con.connect(new SocketTransport(&quot;beagle2.mars.net&quot;, 22),
 * 		&quot;martianx&quot;);
 * 
 * PasswordAuthentication pwd = new PasswordAuthentication();
 * pwd.setPassword(&quot;likeidgivethataway!&quot;);
 * 
 * if (!ssh.isAuthenticated()) {
 * 	if (ssh.authenticate(pwd) == SshAuthentication.COMPLETE) {
 * 		// Transfer some files or do something else interesting
 * 	}
 * }
 * </pre>
 * 
 * </blockquote>
 * </p>
 * <p>
 * It is recommended that in situations where you may be connecting to an SSH2
 * server, that the <a
 * href="../ssh2/Ssh2PasswordAuthentication.html">Ssh2PasswordAuthentication</a>
 * subclass is used instead. This extends the basic functionality provided here
 * by supporting the changing of the users password.
 * </p>
 * 
 * @see com.sshtools.ssh2.Ssh2PasswordAuthentication
 * @author Lee David Painter
 */
public class PasswordAuthentication implements SshAuthentication {

	String password;
	String username;

	/**
	 * Set the password.
	 * 
	 * @param password
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Get the password.
	 * 
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}

	public String getMethod() {
		return "password";
	}

	/**
	 * Set the username.
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * Get the username.
	 */
	public String getUsername() {
		return username;
	}
}

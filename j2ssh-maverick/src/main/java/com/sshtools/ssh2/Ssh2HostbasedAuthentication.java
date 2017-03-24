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
package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshDsaPublicKey;
import com.sshtools.ssh.components.SshPrivateKey;
import com.sshtools.ssh.components.SshPublicKey;
import com.sshtools.ssh.components.SshRsaPublicKey;
import com.sshtools.util.ByteArrayWriter;

/**
 * Provides hostbased authentication for the SSH2 protocol. Hostbased
 * authentication allows a user to connect from a trusted client by providing
 * the clients public key and their local/remote usernames. The server then
 * allows access if the client can be verified through a combination of several
 * different configuration files which include /etc/hosts.equiv
 * /etc/ssh/ssh_known_hosts ~/.ssh/known_hosts ~/.rhosts ~./shosts.
 * 
 * @author Lee David Painter
 */
public class Ssh2HostbasedAuthentication implements AuthenticationClient {

	String clientHostname;
	String username;
	String clientUsername;
	SshPrivateKey prv;
	SshPublicKey pub;

	public void authenticate(AuthenticationProtocol authentication,
			String servicename) throws SshException, AuthenticationResult {

		if (username == null) {
			throw new SshException("Username not set!",
					SshException.BAD_API_USAGE); // SSHException
		}

		if (clientHostname == null)
			throw new SshException("Client hostname not set!",
					SshException.BAD_API_USAGE); // SSHException

		if (clientUsername == null)
			clientUsername = username;

		if (prv == null || pub == null)
			throw new SshException("Client host keys not set!",
					SshException.BAD_API_USAGE);

		if (!(pub instanceof SshRsaPublicKey)
				&& !(pub instanceof SshDsaPublicKey))
			throw new SshException(
					"Invalid public key type for SSH2 authentication!",
					SshException.BAD_API_USAGE);
		ByteArrayWriter msg = new ByteArrayWriter();
		ByteArrayWriter baw = new ByteArrayWriter();
		ByteArrayWriter sig = new ByteArrayWriter();
		try {
			// Generate the message
			msg.writeString(pub.getAlgorithm());
			msg.writeBinaryString(pub.getEncoded());
			msg.writeString(clientHostname);
			msg.writeString(clientUsername);

			// Generate the data to sign

			baw.writeBinaryString(authentication.getSessionIdentifier());
			baw.write(AuthenticationProtocol.SSH_MSG_USERAUTH_REQUEST);
			baw.writeString(username);
			baw.writeString(servicename);
			baw.writeString("hostbased");
			baw.writeString(pub.getAlgorithm());
			baw.writeBinaryString(pub.getEncoded());
			baw.writeString(clientHostname);
			baw.writeString(clientUsername);

			// Format the signature correctly

			sig.writeString(prv.getAlgorithm());
			sig.writeBinaryString(prv.sign(baw.toByteArray()));

			msg.writeBinaryString(sig.toByteArray());

			// Send out request
			authentication.sendRequest(getUsername(), servicename, "hostbased",
					msg.toByteArray());
			byte[] reply = authentication.readMessage();

			throw new SshException(
					"Unexpected message returned from authentication protocol: "
							+ reply[0], SshException.PROTOCOL_VIOLATION);
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				msg.close();
			} catch (IOException e) {
			}
			try {
				baw.close();
			} catch (IOException e) {
			}
			try {
				sig.close();
			} catch (IOException e) {
			}

		}
	}

	public String getMethod() {
		return "hostbased";
	}

	/**
	 * Set the hostname of the client
	 * 
	 * @param clientHostname
	 */
	public void setClientHostname(String clientHostname) {
		this.clientHostname = clientHostname;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getUsername() {
		return username;
	}

	/**
	 * Set the public key for the authentication attempt
	 * 
	 * @param pub
	 */
	public void setPublicKey(SshPublicKey pub) {
		this.pub = pub;
	}

	/**
	 * Set the private key for the authentication attempt
	 * 
	 * @param prv
	 */
	public void setPrivateKey(SshPrivateKey prv) {
		this.prv = prv;
	}

	/**
	 * Set the user's username on the client computer
	 * 
	 * @param clientUsername
	 */
	public void setClientUsername(String clientUsername) {
		this.clientUsername = clientUsername;
	}

	/**
	 * Get the user's username on the client computer
	 * 
	 * @return String
	 */
	public String getClientUsername() {
		return clientUsername;
	}

	/**
	 * Get the private key used for this authentication
	 * 
	 * @return SshPrivateKey
	 */
	public SshPrivateKey getPrivateKey() {
		return prv;
	}

	/**
	 * Set the public key used for this authentication
	 * 
	 * @return SshPublicKey
	 */
	public SshPublicKey getPublicKey() {
		return pub;
	}

}

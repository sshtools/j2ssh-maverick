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

import com.sshtools.events.Event;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.events.J2SSHEventCodes;
import com.sshtools.ssh.SshAuthentication;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.components.SshKeyExchangeClient;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * 
 * <p>
 * Main implementation of the SSH Authentication Protocol. This class is used by
 * <a href="AuthenticationClient.html">AuthenticationClient</a> implementations
 * and exposes a <a href="#readMessage()">readMessage()</a> method that is used
 * to read authentication method specific messages and <a href=
 * "#sendRequest(java.lang.String, java.lang.String, java.lang.String, byte[])">
 * sendRequest</a> method to send authenticaiton requests.
 * </p>
 * .
 * <p>
 * By using these method's the protocol is also able to detect when
 * authentication has succeeded or failed and when this happens an <a
 * href="AuthenticationResult.html">AuthenticationResult</a> is thrown. The
 * following detailed example shows how to use at the higest level. See the <a
 * href="PasswordAuthentication.html">PasswordAuthentication</a> implementation
 * for how to implement such a method. <blockquote>
 * 
 * <pre>
 * try {
 * 	TransportProtocol transport = new TransportProtocol();
 * 	transport.ignoreHostKeyVerification(true);
 * 	transport.startTransportProtocol(new SocketProvider(&quot;mars&quot;, 10022));
 * 
 * 	AuthenticationProtocol authentication = new AuthenticationProtocol(
 * 			transport);
 * 
 * 	authentication.setBannerDisplay(new BannerDisplay() {
 * 		public void displayBanner(String message) {
 * 			System.out.println(message);
 * 
 * 			try {
 * 				System.out.println(&quot;Press enter to continue...&quot;);
 * 				System.in.read();
 * 			} catch (Exception e) {
 * 			}
 * 			;
 * 		}
 * 	});
 * 
 * 	StringTokenizer tokens = new StringTokenizer(
 * 			authentication.getAuthenticationMethods(&quot;lee&quot;, &quot;ssh-connection&quot;),
 * 			&quot;,&quot;);
 * 
 * 	int count = 1;
 * 
 * 	System.out.println(&quot;Available authentication methods&quot;);
 * 
 * 	while (tokens.hasMoreElements()) {
 * 		System.out.println(String.valueOf(count++) + &quot;. &quot;
 * 				+ tokens.nextElement());
 * 	}
 * 
 * 	System.out.println(&quot;\nAttempting password authentication\n&quot;);
 * 
 * 	PasswordAuthentication pwd = new PasswordAuthentication();
 * 
 * 	int result;
 * 
 * 	BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
 * 	do {
 * 		// Get the username and password if we have not already sent it
 * 		if (!pwd.requiresPasswordChange()) {
 * 
 * 			System.out.print(&quot;Username: &quot;);
 * 			pwd.setUsername(reader.readLine());
 * 
 * 			System.out.print(&quot;Password: &quot;);
 * 			pwd.setPassword(reader.readLine());
 * 		} else {
 * 			// We have already failed and need to change the password.
 * 			System.out.println(&quot;You need to change your password!&quot;);
 * 			System.out.print(&quot;New Password: &quot;);
 * 			pwd.setNewPassword(reader.readLine());
 * 		}
 * 
 * 		result = authentication.authenticate(pwd, &quot;ssh-connection&quot;);
 * 
 * 	} while (result != AuthenticationResult.COMPLETE
 * 			&amp;&amp; result != AuthenticationResult.CANCELLED);
 * 
 * 	System.out.println(&quot;Authentication &quot;
 * 			+ (result == AuthenticationResult.COMPLETE ? &quot;completed&quot;
 * 					: &quot;cancelled&quot;));
 * 
 * } catch (Throwable t) {
 * 	t.printStackTrace();
 * }
 * </pre>
 * 
 * <blockquote>
 * </p>
 * 
 * @author Lee David Painter
 */
public class AuthenticationProtocol {

	public final static int SSH_MSG_USERAUTH_REQUEST = 50;
	final static int SSH_MSG_USERAUTH_FAILURE = 51;
	final static int SSH_MSG_USERAUTH_SUCCESS = 52;
	final static int SSH_MSG_USERAUTH_BANNER = 53;

	TransportProtocol transport;
	BannerDisplay display;
	int state = SshAuthentication.FAILED;

	/** The name of this service "ssh-userauth" */
	public static final String SERVICE_NAME = "ssh-userauth";

	public SshKeyExchangeClient getKeyExchange() {
		return transport.getKeyExchange();
	}

	/**
	 * Construct the protocol using the given transport
	 * 
	 * @param transport
	 * @throws SshException
	 */
	public AuthenticationProtocol(TransportProtocol transport)
			throws SshException {
		this.transport = transport;

		transport.startService("ssh-userauth");
	}

	/**
	 * Set a callback interface for banner messages. It is advisable to pause
	 * processing within the callback implementation to allow the user time to
	 * read and accept the message.
	 * 
	 * @param display
	 */
	public void setBannerDisplay(BannerDisplay display) {
		this.display = display;
	}

	/**
	 * Read a message from the underlying transport layer. This method processes
	 * the incoming message to determine whether it is an
	 * SSH_MSG_USERAUTH_SUCCESS or SSH_MSG_USERAUTH_FAILURE. If these messages
	 * are detected an <a
	 * href="AuthenticationResult.html">AuthenticationResult</a> is thrown.
	 * 
	 * @return the next available message
	 * @throws SshException
	 * @throws AuthenticationResult
	 */
	public byte[] readMessage() throws SshException, AuthenticationResult {

		byte[] msg;

		while (processMessage(msg = transport.nextMessage())) {
			;
		}

		return msg;
	}

	/**
	 * Authenticate using the mechanism provided.
	 * 
	 * @param auth
	 * @param servicename
	 * @return Any of the constants defined in <a
	 *         href="AuthenticationResult.html">AuthenticationResult</a>
	 * @throws SshException
	 */
	public int authenticate(AuthenticationClient auth, String servicename)
			throws SshException {
		try {
			auth.authenticate(this, servicename);
			readMessage();
			transport
					.disconnect(TransportProtocol.PROTOCOL_ERROR,
							"Unexpected response received from Authentication Protocol");
			throw new SshException(
					"Unexpected response received from Authentication Protocol",
					SshException.PROTOCOL_VIOLATION);
		} catch (AuthenticationResult result) {
			state = result.getResult();
			if (state == SshAuthentication.COMPLETE)
				transport.completedAuthentication();
			return state;
		}
	}

	/**
	 * Get a list of available authentication methods for the user. It is
	 * advisable to call this method after contsructing the protocol instance
	 * and setting a <a href="BannerDisplay.html">BannerDisplay</a>. If the
	 * server has a banner message to display it is most likely that the server
	 * will send it before completing this list.
	 * 
	 * @param username
	 * @param servicename
	 * @return a comma delimited list of authentication methods.
	 * @throws SshException
	 */
	public String getAuthenticationMethods(String username, String servicename)
			throws SshException {
		sendRequest(username, servicename, "none", null);

		try {
			readMessage();
			transport
					.disconnect(TransportProtocol.PROTOCOL_ERROR,
							"Unexpected response received from Authentication Protocol");
			throw new SshException(
					"Unexpected response received from Authentication Protocol",
					SshException.PROTOCOL_VIOLATION);
		} catch (AuthenticationResult result) {
			state = result.getResult();
			EventServiceImplementation
					.getInstance()
					.fireEvent(
							(new Event(
									this,
									J2SSHEventCodes.EVENT_AUTHENTICATION_METHODS_RECEIVED,
									true))
									.addAttribute(
											J2SSHEventCodes.ATTRIBUTE_AUTHENTICATION_METHODS,
											result.getAuthenticationMethods()));
			return result.getAuthenticationMethods();
		}
	}

	/**
	 * Send an authentication request. This sends an SSH_MSG_USERAUTH_REQUEST
	 * message.
	 * 
	 * @param username
	 * @param servicename
	 * @param methodname
	 * @param requestdata
	 *            the request data as defined by the authentication
	 *            specification
	 * @throws SshException
	 */
	public void sendRequest(String username, String servicename,
			String methodname, byte[] requestdata) throws SshException {

		ByteArrayWriter msg = new ByteArrayWriter();
		try {

			msg.write(SSH_MSG_USERAUTH_REQUEST);
			msg.writeString(username);
			msg.writeString(servicename);
			msg.writeString(methodname);
			if (requestdata != null) {
				msg.write(requestdata);
			}

			transport.sendMessage(msg.toByteArray(), true);
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				msg.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * Determine whether the protocol has made a sucessfull authentication
	 * attempt.
	 * 
	 * @return <code>true</code> if the user is authenticated, otherwise
	 *         <code>false</code>
	 */
	public boolean isAuthenticated() {
		return state == SshAuthentication.COMPLETE;
	}

	public byte[] getSessionIdentifier() {
		return transport.getSessionIdentifier();
	}

	private boolean processMessage(byte[] msg) throws SshException,
			AuthenticationResult {

		try {
			switch (msg[0]) {
			case SSH_MSG_USERAUTH_FAILURE: {
				ByteArrayReader bar = new ByteArrayReader(msg); // , 6,
																// msg.length -
																// 6);
				try {
					bar.skip(1);
					String auths = bar.readString();
					if (bar.read() == 0) {
						EventServiceImplementation.getInstance().fireEvent(
								new Event(this,
										J2SSHEventCodes.EVENT_USERAUTH_FAILURE,
										true));
						throw new AuthenticationResult(
								SshAuthentication.FAILED, auths);
					}
					EventServiceImplementation
							.getInstance()
							.fireEvent(
									new Event(
											this,
											J2SSHEventCodes.EVENT_USERAUTH_FURTHER_AUTHENTICATION_REQUIRED,
											true));
					throw new AuthenticationResult(
							SshAuthentication.FURTHER_AUTHENTICATION_REQUIRED,
							auths);
				} finally {
					bar.close();
				}
			}
			case SSH_MSG_USERAUTH_SUCCESS: {
				EventServiceImplementation.getInstance().fireEvent(
						new Event(this, J2SSHEventCodes.EVENT_USERAUTH_SUCCESS,
								true));
				throw new AuthenticationResult(SshAuthentication.COMPLETE);
			}
			case SSH_MSG_USERAUTH_BANNER: {
				ByteArrayReader bar = new ByteArrayReader(msg); // , 6,
																// msg.length -
																// 6);
				try {
					bar.skip(1);

					// Show the banner on the current display or print to stdout
					if (display != null) {
						display.displayBanner(bar.readString());
					}
					return true;
				} finally {
					bar.close();
				}
			}
			default:
				return false;
			}
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}
	}

	public void sendMessage(byte[] messg) throws SshException {
		transport.sendMessage(messg, true);
	}

	public String getHost() {
		return transport.provider.getHost();
	}

}

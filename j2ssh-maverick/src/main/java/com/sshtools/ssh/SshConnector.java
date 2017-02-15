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

import java.io.IOException;
import java.io.InputStream;

import com.sshtools.events.EventListener;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.logging.Log;
import com.sshtools.ssh2.Ssh2Client;
import com.sshtools.ssh2.Ssh2Context;

/**
 * <p>
 * This utility class establishes a connection with an SSH server, determines
 * which SSH protocol versions are supported and creates an initialized
 * connection ready for authentication.
 * <p>
 * 
 * <p>
 * Each call to <a href="#createInstance()">createInstance()</a> returns a new
 * instance of the connector with a configuration context. These are designed to
 * be re-used for many connections where the same configuration can be used.
 * <p>
 * 
 * <p>
 * To connect to an SSH server you need to provide an <a
 * href="SshTransport.html">SshTransport</a> which provides the transport layer
 * communication. In most cases this will be a Socket however since this API is
 * designed for many different platforms, a Socket may not always be available
 * so this simple interface is used to allow you to specify the source IO
 * streams. The <a href="SshTransport.html">SshTransport</a> documentation
 * provides a simple example for a Socket called <a
 * href="SshTransport#SocketTransport">SocketTransport</a> which is used in the
 * following examples.
 * </p>
 * 
 * <p>
 * To create a connection and authentication using password authentication with
 * default configuration contexts use: <blockquote>
 * 
 * <pre>
 * SshConnector con = SshConnector.createInstance();
 * SshClient ssh = con.connect(new SocketTransport(&quot;beagle2.sshtools.net&quot;, 22),
 * 		&quot;martianx&quot;);
 * 
 * PasswordAuthentication pwd = new PasswordAuthentication();
 * pwd.setPassword(&quot;likeidgivethataway!&quot;);
 * 
 * if (ssh.authenticate(pwd) == SshAuthentication.COMPLETE) {
 * 	System.out.println(&quot;Authentication succeeded&quot;);
 * 	SshSession sesison = ssh.openSessionChannel();
 * } else {
 * 	System.out.println(&quot;Authentication failed&quot;);
 * }
 * </pre>
 * 
 * </blockquote>
 * </p>
 * 
 * @author Lee David Painter
 */
public final class SshConnector {

	String softwareComments = "SOFTWARE_VERSION_COMMENTS";
	String originalSoftwareComments = "SOFTWARE_VERSION_COMMENTS";

	Ssh2Context ssh2Context;
	String product = "J2SSH";

	public static Throwable initException = null;

	boolean fipsEnabled = false;

	SshConnector() throws SshException {
		ssh2Context = new Ssh2Context();
	}

	/**
	 * Returns an instance of the <code>SshConnector</code>. Each instance is
	 * initialized with a pair of default contexts.
	 * 
	 * @return a new instance
	 * @throws SshException
	 */
	public static SshConnector createInstance() throws SshException {
		return new SshConnector();
	}

	public static void addEventListener(EventListener listener) {
		EventServiceImplementation.getInstance().addListener("", listener);
	}

	public static void addEventListener(String threadPrefix,
			EventListener listener) {
		EventServiceImplementation.getInstance().addListener(threadPrefix,
				listener);
	}

	public static void removeEventListener(String threadPrefix) {
		EventServiceImplementation.getInstance().removeListener(threadPrefix);
	}

	public final void enableFIPSMode() throws SshException {
		ssh2Context.enableFIPSMode();
		fipsEnabled = true;
	}

	/**
	 * <p>
	 * Get the configuration context.
	 * 
	 * @return the version context
	 * @throws SshException
	 */
	public Ssh2Context getContext() throws SshException {
		return ssh2Context;
	}

	/**
	 * <p>
	 * Create a new connection to an SSH server over the specified transport.
	 * This method reads the remote servers identification and determines which
	 * protocol support is required. An {@link SshClient} instance is then
	 * created, initialized and returned. If both protocol versions are
	 * supported by the remote server the connector will always operate using
	 * SSH2.
	 * <p>
	 * 
	 * <p>
	 * The {@link SshTransport} interface is used here to allow different types
	 * of transport mechanisms. Typically this would be a Socket however since
	 * this API is targeted at all Java platforms a Socket cannot be used
	 * directly. See the {@link SshTransport} documentation for an example
	 * Socket implementation.
	 * <p>
	 * 
	 * 
	 * @param transport
	 *            the transport for the connection.
	 * @param username
	 *            the name of the user connecting
	 * @return a connected <a href="SshClient.html">SshClient</a> instance ready
	 *         for authentication.
	 * @see com.sshtools.ssh2.Ssh2Client
	 * @throws SshException
	 */
	public Ssh2Client connect(SshTransport transport, String username)
			throws SshException {
		return connect(transport, username, false, null);
	}

	/**
	 * See {@link connect(SshTransport, String)} for full details. This method
	 * optionally allows you to specify the buffered state of the connection.
	 * When the connection is buffered a background thread is started to act as
	 * a message pump; this has the benefit of routing data as soon as it
	 * arrives and helps in circumstances where you require a channel to fill up
	 * with data without calling its InputStream's read method. This also will
	 * enable the InputStreams available method to work as expected.
	 * 
	 * @param transport
	 *            SshTransport
	 * @param username
	 *            String
	 * @param buffered
	 *            boolean
	 * @return SshClient
	 * @throws SshException
	 */
	public SshClient connect(SshTransport transport, String username,
			boolean buffered) throws SshException {
		return connect(transport, username, buffered, null);
	}

	/**
	 * See {@link connect(SshTransport, String)} for full details. This method
	 * optionally allows you to specify a context to use. Normally you would
	 * reused an {@link SshConnector} instead of calling this method directly.
	 * 
	 * @param transport
	 *            SshTransport
	 * @param username
	 *            String
	 * @param context
	 *            SshContext
	 * @return SshClient
	 * @throws SshException
	 */
	public SshClient connect(SshTransport transport, String username,
			SshContext context) throws SshException {
		return connect(transport, username, false, context);
	}

	/**
	 * Set the software/version/comments field of the SSH identification string
	 * 
	 * @param softwareComments
	 *            String
	 */
	public void setSoftwareVersionComments(String softwareComments) {
		this.softwareComments = softwareComments;
	}

	/**
	 * See {@link connect(SshTransport, String)} for full details.
	 * 
	 * <p>
	 * This method optionally allows you to specify the buffered state of the
	 * connection. When the connection is buffered a background thread is
	 * started to act as a message pump; this has the benefit of routing data as
	 * soon as it arrives and helps in circumstances where you require a channel
	 * to fill up with data without calling its InputStream's read method. This
	 * also will enable the InputStreams available method to work as expected.
	 * </p>
	 * 
	 * <p>
	 * This method also allows you to specify a context to use. Normally you
	 * would reuse an {@link SshConnector} instead of calling this method
	 * directly.
	 * </p>
	 * 
	 * @param transport
	 *            SshTransport
	 * @param username
	 *            String
	 * @param buffered
	 *            boolean
	 * @param context
	 *            SshContext
	 * @return SshClient
	 * @throws SshException
	 */
	public Ssh2Client connect(SshTransport transport, String username,
			boolean buffered, SshContext context) throws SshException {

		if (Log.isDebugEnabled()) {
			Log.debug(this,
					"Connecting " + username + "@" + transport.getHost() + ":"
							+ transport.getPort() + " [buffered=" + buffered
							+ "]");
		}

		// Lets first try SSH2 cause its a better protocol
		Ssh2Client client;
		String localIdentification = null;
		String remoteIdentification = null;

		localIdentification = "SSH-2.0-" + softwareComments.replace(' ', '_');

		if (localIdentification.length() > 253) {
			localIdentification = localIdentification.substring(0, 253);
		}

		localIdentification += "\r\n";

		Ssh2Context ctx = (Ssh2Context) (context != null ? context
				: ssh2Context);
		if (ctx.getSocketTimeout() > 0
				&& transport instanceof SocketTimeoutSupport) {
			try {
				((SocketTimeoutSupport) transport).setSoTimeout(ctx
						.getSocketTimeout());
			} catch (IOException e) {
				throw new SshException(SshException.CONNECT_FAILED, e);
			}
		} else if (ctx.getSocketTimeout() > 0) {
			Log.info(
					this,
					"Socket timeout is set on SshContext but SshTransport does not support socket timeouts");
		}

		if (Log.isDebugEnabled()) {
			Log.debug(this, "Attempting to determine remote version");
		}

		remoteIdentification = getRemoteIdentification(transport);

		try {

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Attempting SSH2 connection");
			}

			transport.getOutputStream().write(localIdentification.getBytes());

			client = new Ssh2Client();

			if (Log.isDebugEnabled()) {
				Log.debug(this, "Remote identification: "
						+ remoteIdentification);
				Log.debug(this, "Local identification: "
						+ localIdentification.trim() + " ["
						+ originalSoftwareComments + "]");
			}

			client.connect(transport, ssh2Context == null ? context
					: ssh2Context, this, username, localIdentification.trim(),
					remoteIdentification, buffered);
			return client;
		} catch (Throwable t) {
			throw new SshException(t.getMessage() != null ? t.getMessage() : t
					.getClass().getName(), SshException.CONNECT_FAILED, t);

		}
	}

	String getRemoteIdentification(SshTransport transport) throws SshException {

		try {
			String remoteIdentification = "";

			// Now wait for a reply and evaluate the ident string
			StringBuffer lineBuffer;
			InputStream in = transport.getInputStream();

			int MAX_BUFFER_LENGTH = 255;

			// Look for a string starting with "SSH-"
			while (!remoteIdentification.startsWith("SSH-")) {
				// Get the next string
				int ch;
				// reset line buffer to new empty StringBuffer
				lineBuffer = new StringBuffer(MAX_BUFFER_LENGTH);
				while (((ch = in.read()) != '\n')
						&& (lineBuffer.length() < MAX_BUFFER_LENGTH) && ch > -1) {
					if (ch == '\r') {
						continue;
					}
					lineBuffer.append((char) ch);
				}

				if (ch == -1) {
					throw new SshException(
							"Failed to read remote identification "
									+ lineBuffer.toString(),
							SshException.CONNECT_FAILED);
				}
				// Set trimming off any EOL characters
				remoteIdentification = lineBuffer.toString();
			}

			return remoteIdentification;
		} catch (Throwable ex) {
			throw new SshException(ex, SshException.CONNECT_FAILED);
		}
	}

	public String getProduct() {
		return product;
	}

	public void setProduct(String product) {
		this.product = product;
	}

}

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

package com.sshtools.ssh2;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import com.sshtools.events.EventLog;
import com.sshtools.ssh.ChannelEventListener;
import com.sshtools.ssh.ChannelOpenException;
import com.sshtools.ssh.ForwardingRequestListener;
import com.sshtools.ssh.PasswordAuthentication;
import com.sshtools.ssh.PublicKeyAuthentication;
import com.sshtools.ssh.SshAuthentication;
import com.sshtools.ssh.SshClient;
import com.sshtools.ssh.SshConnector;
import com.sshtools.ssh.SshContext;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshSession;
import com.sshtools.ssh.SshTransport;
import com.sshtools.ssh.SshTunnel;
import com.sshtools.ssh.components.SshKeyExchangeClient;
import com.sshtools.ssh.message.SshAbstractChannel;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
 * <p>
 * Implementation of an <a href="../ssh/SshClient.html">SshClient</a> for the
 * SSH2 protocol; this provides the ability to create custom channels and
 * sending/receiving of global requests in addition to the standard <a
 * href="../ssh/SshClient.html">SshClient</a> contract.
 * </p>
 * 
 * @author Lee David Painter
 */
public class Ssh2Client implements SshClient {

	TransportProtocol transport;
	SshTransport io;
	AuthenticationProtocol authentication;
	ConnectionProtocol connection;
	String localIdentification;
	String remoteIdentification;
	String[] authenticationMethods;
	String username;
	Hashtable forwardingListeners = new Hashtable();
	Hashtable forwardingDestinations = new Hashtable();
	ForwardingRequestChannelFactory requestFactory = new ForwardingRequestChannelFactory();
	SshAuthentication auth;
	SshConnector connector;
	boolean isXForwarding = false;
	boolean buffered;

	/**
	 * Default constructor called by <a
	 * href="../ssh/SshConnector.html">SshConnector</a>.
	 * 
	 */
	public Ssh2Client() {
	}

	public void connect(SshTransport io, SshContext context,
			SshConnector connector, String username,
			String localIdentification, String remoteIdentification,
			boolean buffered) throws SshException {

		this.io = io;
		this.localIdentification = localIdentification;
		this.remoteIdentification = remoteIdentification;
		this.username = username;
		this.buffered = buffered;
		this.connector = connector;

		if (username == null) {
			try {
				io.close();
			} catch (IOException ex) {
				// #ifdef DEBUG
				EventLog.LogEvent(
						this,
						"RECIEVED IOException IN Ssh2Client.connect:"
								+ ex.getMessage());
				// #endif
			}
			throw new SshException("You must supply a valid username!",
					SshException.BAD_API_USAGE);
		}

		if (!(context instanceof Ssh2Context)) {
			try {
				io.close();
			} catch (IOException ex) {
				// #ifdef DEBUG
				EventLog.LogEvent(
						this,
						"RECIEVED IOException IN Ssh2Client.connect:"
								+ ex.getMessage());
				// #endif

			}
			throw new SshException("Ssh2Context required!",
					SshException.BAD_API_USAGE);
		}

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Connecting " + username + "@" + io.getHost()
				+ ":" + io.getPort());
		EventLog.LogDebugEvent(this, "Remote identification is "
				+ remoteIdentification);
		// #endif

		transport = new TransportProtocol();

		// #ifdef DEBUG
		EventLog.LogDebugEvent(this, "Starting transport protocol");
		// #endif

		transport.startTransportProtocol(io, (Ssh2Context) context,
				localIdentification, remoteIdentification, this);

		// #ifdef DEBUG
		EventLog.LogDebugEvent(this, "Starting authentication protocol");
		// #endif

		authentication = new AuthenticationProtocol(transport);
		authentication.setBannerDisplay(((Ssh2Context) context)
				.getBannerDisplay());

		connection = new ConnectionProtocol(this.transport, context, buffered);
		connection.addChannelFactory(requestFactory);

		getAuthenticationMethods(username);
		
		// #ifdef DEBUG
		EventLog.LogEvent(this, "SSH connection established");
		// #endif
	}

	/**
	 * Get a list of authentication methods for the user.
	 * 
	 * @param username
	 *            the name of the user
	 * @return an array of authentication methods, for example { "password",
	 *         "publickey" }
	 * @throws SshException
	 */
	public String[] getAuthenticationMethods(String username)
			throws SshException {
		verifyConnection(false);

		if (authenticationMethods == null) {

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Requesting authentication methods");
			// #endif

			String methods = authentication.getAuthenticationMethods(username,
					ConnectionProtocol.SERVICE_NAME);

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Available authentications are " + methods);
			// #endif
			Vector tmp = new Vector();
			int idx;
			while (methods != null) {
				idx = methods.indexOf(',');
				if (idx > -1) {
					tmp.addElement(methods.substring(0, idx));
					methods = methods.substring(idx + 1);
				} else {
					tmp.addElement(methods);
					methods = null;
				}
			}
			authenticationMethods = new String[tmp.size()];
			tmp.copyInto(authenticationMethods);

			/*
			 * if there are no authentication methods, then check if
			 * isAuthenticated if isAuthenticated then need to start the message
			 * pump, as authenticate will not be called
			 */
			if (isAuthenticated()) {
				connection.start();
			}
		}

		return authenticationMethods;
	}

	/**
	 * this method is called if a user attempts password authentication it
	 * determines whether password authentication is possible. if it isnt, but
	 * keyboard interactive is possible, it authenticates using that instead
	 */
	private SshAuthentication checkForPasswordOverKBI(SshAuthentication auth) {
		boolean kbiAuthenticationPossible = false;
		for (int i = 0; i < authenticationMethods.length; i++) {
			if (authenticationMethods[i].equals("password")) {
				// password authentication is possible so return auth unchanged
				return auth;
			}
			if ((authenticationMethods[i].equals("keyboard-interactive"))) {
				// if none of the subsequent methods are password then have
				// option to use kbi instead
				kbiAuthenticationPossible = true;
			}
		}
		// password is not possible, so attempt kbi
		if (kbiAuthenticationPossible) {
			// create KBIAuthentication instance
			KBIAuthentication kbi = new KBIAuthentication();
			// set the username that the user entered
			kbi.setUsername(((PasswordAuthentication) auth).getUsername());

			// set request handler, that sets the password the user entered as
			// response to any prompts
			kbi.setKBIRequestHandler(new KBIRequestHandlerWhenUserUsingPasswordAuthentication(
					(PasswordAuthentication) auth));

			return kbi;
		}
		// neither password nor kbi is possible so return auth unchanged so that
		// the normal error message is returned
		return auth;
	}

	/**
	 * <p>
	 * Request handler that sets the password the user entered as response to
	 * any prompts
	 * </p>
	 * 
	 * @author David Hodgins
	 */
	private static class KBIRequestHandlerWhenUserUsingPasswordAuthentication
			implements KBIRequestHandler {
		private String password;

		public KBIRequestHandlerWhenUserUsingPasswordAuthentication(
				PasswordAuthentication pwdAuth) {
			password = pwdAuth.getPassword();
		}

		/**
		 * Called by the <em>keyboard-interactive</em> authentication mechanism
		 * when the server requests information from the user. Each prompt
		 * should be displayed to the user with their response recorded within
		 * the prompt object.
		 * 
		 * @param name
		 * @param instruction
		 * @param prompts
		 */
		public boolean showPrompts(String name, String instruction,
				KBIPrompt[] prompts) {
			for (int i = 0; i < prompts.length; i++) {
				prompts[i].setResponse(password);
			}
			return true;
		}

	}

	public int authenticate(SshAuthentication auth) throws SshException {
		verifyConnection(false);

		if (isAuthenticated())
			throw new SshException(
					"User is already authenticated! Did you check isAuthenticated?",
					SshException.BAD_API_USAGE);

		if (auth.getUsername() == null) {
			auth.setUsername(username);
		}

		if (auth instanceof PasswordAuthentication
				|| auth instanceof Ssh2PasswordAuthentication) {
			auth = checkForPasswordOverKBI(auth);
		}

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Authenticating with " + auth.getMethod());
		// #endif

		int result;

		if (auth instanceof PasswordAuthentication
				&& !(auth instanceof Ssh2PasswordAuthentication)) {
			// We need to create an instance of Ssh2PasswordAuthentication
			Ssh2PasswordAuthentication pwd = new Ssh2PasswordAuthentication();
			pwd.setUsername(((PasswordAuthentication) auth).getUsername());
			pwd.setPassword(((PasswordAuthentication) auth).getPassword());

			result = authentication.authenticate(pwd,
					ConnectionProtocol.SERVICE_NAME);

			if (pwd.requiresPasswordChange()) {
				disconnect();
				throw new SshException("Password change required!",
						SshException.CANCELLED_CONNECTION);
			}
		} else if (auth instanceof PublicKeyAuthentication
				&& !(auth instanceof Ssh2PublicKeyAuthentication)) {
			// We need to create an Ssh2PublicKeyAuthentication object
			Ssh2PublicKeyAuthentication pk = new Ssh2PublicKeyAuthentication();
			pk.setUsername(((PublicKeyAuthentication) auth).getUsername());
			pk.setPublicKey(((PublicKeyAuthentication) auth).getPublicKey());
			pk.setPrivateKey(((PublicKeyAuthentication) auth).getPrivateKey());

			result = authentication.authenticate(pk,
					ConnectionProtocol.SERVICE_NAME);

		} else if (auth instanceof AuthenticationClient) {
			// Execute an AuthenticationClient instance
			result = authentication.authenticate((AuthenticationClient) auth,
					ConnectionProtocol.SERVICE_NAME);
		} else {
			throw new SshException("Invalid authentication client",
					SshException.BAD_API_USAGE);
		}

		if (result == SshAuthentication.COMPLETE) {
			this.auth = auth;
			connection.start();
		}

		// #ifdef DEBUG
		switch (result) {
		case SshAuthentication.COMPLETE:
			EventLog.LogEvent(this, "Authentication complete");
			break;
		case SshAuthentication.FAILED:
			EventLog.LogEvent(this, "Authentication failed");
			break;
		case SshAuthentication.FURTHER_AUTHENTICATION_REQUIRED:
			EventLog.LogEvent(this,
					"Authentication successful but further authentication required");
			break;
		case SshAuthentication.CANCELLED:
			EventLog.LogEvent(this, "Authentication cancelled");
			break;
		case SshAuthentication.PUBLIC_KEY_ACCEPTABLE:
			EventLog.LogEvent(this, "Server accepts the public key provided");
			break;
		default:
			EventLog.LogErrorEvent(this, "Unknown authentication result "
					+ result);
			break;
		}
		// #endif

		return result;
	}

	public boolean isAuthenticated() {
		return authentication.isAuthenticated();
	}

	public void disconnect() {

		try {

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Disconnecting");
			// #endif
			connection.signalClosingState();
			connection.stop();
			transport.disconnect(TransportProtocol.BY_APPLICATION,
					"The user disconnected the application");
		} catch (Throwable t) {
		} 

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Disconnected");
		// #endif
	}

	public void exit() {

		try {

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Disconnecting");
			// #endif
			connection.signalClosingState();
			transport.disconnect(TransportProtocol.BY_APPLICATION,
					"The user disconnected the application");
		} catch (Throwable t) {
		}

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Disconnected");
		// #endif
	}

	public boolean isConnected() {
		return transport.isConnected();
	}

	/**
	 * The SSH transport protocol exchanges keys at the beginning of the
	 * session; the specification recommends that these keys be re-exchanged
	 * after each gigabyte of transmitted data or after each hour of connection
	 * time, whichever comes sooner. This method can be called at anytime to
	 * begin the key exchange process.
	 * 
	 * @throws SshException
	 */
	public void forceKeyExchange() throws SshException {
		// #ifdef DEBUG
		EventLog.LogEvent(this, "Forcing key exchange");
		// #endif
		transport.sendKeyExchangeInit(false);
	}

	public SshSession openSessionChannel() throws SshException,
			ChannelOpenException {
		return openSessionChannel(32768, 32768, null);
	}

	public SshSession openSessionChannel(long timeout) throws SshException,
			ChannelOpenException {
		return openSessionChannel(32768, 32768, null, timeout);
	}

	public SshSession openSessionChannel(ChannelEventListener listener,
			long timeout) throws SshException, ChannelOpenException {
		return openSessionChannel(32768, 32768, listener, timeout);
	}

	public SshSession openSessionChannel(ChannelEventListener listener)
			throws SshException, ChannelOpenException {
		return openSessionChannel(32768, 32768, listener);
	}

	/**
	 * Additional method to open a session with SSH2 specific features.
	 * 
	 * @param windowspace
	 *            the initial amount of window space available
	 * @param packetsize
	 *            the maximum packet size
	 * @param listener
	 *            an event listener to add before opening
	 * @return an open session
	 * @throws SshException
	 * @throws ChannelOpenException
	 */
	public Ssh2Session openSessionChannel(int windowspace, int packetsize,
			ChannelEventListener listener) throws ChannelOpenException,
			SshException {
		return openSessionChannel(windowspace, packetsize, listener, 0);
	}

	public Ssh2Session openSessionChannel(int windowspace, int packetsize,
			ChannelEventListener listener, long timeout)
			throws ChannelOpenException, SshException {
		verifyConnection(true);

		// #ifdef DEBUG
		EventLog.LogEvent(this, "Opening session channel windowspace="
				+ windowspace + " packetsize=" + packetsize);
		// #endif

		Ssh2Session channel = new Ssh2Session(windowspace, packetsize, this);
		if (listener != null) {
			channel.addChannelEventListener(listener);
		}

		connection.openChannel(channel, null, timeout);

		// #ifdef DEBUG
		EventLog.LogEvent(this,
				"Channel has been opened channelid=" + channel.getChannelId());
		// #endif

		/**
		 * Do our sessions require x forwarding? If so then request and make
		 * sure our XForwarding Channel Factory is active.
		 */
		if (connection.getContext().getX11Display() != null) {

			String display = connection.getContext().getX11Display();

			int idx = display.indexOf(':');
			int screen = 0;
			if (idx != -1) {
				display = display.substring(idx + 1);
			}

			idx = display.indexOf('.');

			if (idx > -1) {
				screen = Integer.parseInt(display.substring(idx + 1));
			}

			byte[] x11FakeCookie = connection.getContext()
					.getX11AuthenticationCookie();
			StringBuffer cookieBuf = new StringBuffer();
			for (int i = 0; i < 16; i++) {
				String b = Integer.toHexString(x11FakeCookie[i] & 0xff);
				if (b.length() == 1) {
					b = "0" + b;
				}
				cookieBuf.append(b);
			}

			if (channel.requestX11Forwarding(false, "MIT-MAGIC-COOKIE-1",
					cookieBuf.toString(), screen)) {
				isXForwarding = true;
			}

		}
		return channel;
	}

	public SshClient openRemoteClient(String hostname, int port,
			String username, SshConnector con) throws SshException,
			ChannelOpenException {

		// #ifdef DEBUG
		EventLog.LogEvent(this,
				"Opening a remote SSH client from " + io.getHost() + " to "
						+ username + "@" + hostname + ":" + port);
		// #endif
		SshTunnel tunnel = openForwardingChannel(hostname, port, "127.0.0.1",
				22, "127.0.0.1", 22, null, null);

		return con.connect(tunnel, username, buffered);

	}

	public SshClient openRemoteClient(String hostname, int port, String username)
			throws SshException, ChannelOpenException {
		return openRemoteClient(hostname, port, username, connector);
	}

	public SshTunnel openForwardingChannel(String hostname, int port,
			String listeningAddress, int listeningPort, String originatingHost,
			int originatingPort, SshTransport transport,
			ChannelEventListener listener) throws SshException,
			ChannelOpenException {
		try {

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Opening forwarding channel from "
					+ listeningAddress + ":" + listeningPort + " to "
					+ hostname + ":" + port);
			// #endif

			Ssh2ForwardingChannel tunnel = new Ssh2ForwardingChannel(
					Ssh2ForwardingChannel.LOCAL_FORWARDING_CHANNEL, 32768,
					2097152, hostname, port, listeningAddress, listeningPort,
					originatingHost, originatingPort, transport);

			ByteArrayWriter request = new ByteArrayWriter();
			request.writeString(hostname);
			request.writeInt(port);
			request.writeString(originatingHost);
			request.writeInt(originatingPort);

			tunnel.addChannelEventListener(listener);

			openChannel(tunnel, request.toByteArray());
			return tunnel;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}
	}

	public boolean requestRemoteForwarding(String bindAddress, int bindPort,
			String hostToConnect, int portToConnect,
			ForwardingRequestListener listener) throws SshException {

		try {
			if (listener == null) {
				throw new SshException(
						"You must specify a listener to receive connection requests",
						SshException.BAD_API_USAGE);
			}

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Requesting remote forwarding from "
					+ bindAddress + ":" + bindPort + " to " + hostToConnect
					+ ":" + portToConnect);
			// #endif

			ByteArrayWriter baw = new ByteArrayWriter();
			baw.writeString(bindAddress);
			baw.writeInt(bindPort);
			GlobalRequest request = new GlobalRequest("tcpip-forward",
					baw.toByteArray());

			if (sendGlobalRequest(request, true)) {

				forwardingListeners.put(
						(bindAddress + ":" + String.valueOf(bindPort)),
						listener);
				forwardingDestinations.put(
						(bindAddress + ":" + String.valueOf(bindPort)),
						(hostToConnect + ":" + String.valueOf(portToConnect)));
				// Setup the forwarding listener
				return true;
			}
			return false;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}

	}

	public boolean cancelRemoteForwarding(String bindAddress, int bindPort)
			throws SshException {

		try {

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Cancelling remote forwarding from "
					+ bindAddress + ":" + bindPort);
			// #endif

			ByteArrayWriter baw = new ByteArrayWriter();
			baw.writeString(bindAddress);
			baw.writeInt(bindPort);
			GlobalRequest request = new GlobalRequest("cancel-tcpip-forward",
					baw.toByteArray());

			if (sendGlobalRequest(request, true)) {

				forwardingListeners.remove(bindAddress + ":"
						+ String.valueOf(bindPort));
				forwardingDestinations.remove(bindAddress + ":"
						+ String.valueOf(bindPort));

				return true;
			}

			return false;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}
	}

	/**
	 * Additional method to open a custom SSH2 channel.
	 * 
	 * @param channel
	 *            the channel to open
	 * @param requestdata
	 *            the request data
	 * @throws SshException
	 * @throws ChannelOpenException
	 */
	public void openChannel(Ssh2Channel channel, byte[] requestdata)
			throws SshException, ChannelOpenException {
		verifyConnection(true);
		connection.openChannel(channel, requestdata);
	}

	/**
	 * Additional method to open a custom SSH2 channel.
	 * 
	 * @param channel
	 *            the channel to open
	 * @throws SshException
	 * @throws ChannelOpenException
	 */
	public void openChannel(SshAbstractChannel channel) throws SshException,
			ChannelOpenException {
		verifyConnection(true);
		if (channel instanceof Ssh2Channel) {
			connection.openChannel((Ssh2Channel) channel, null);
		} else {
			throw new SshException("The channel is not an SSH2 channel!",
					SshException.BAD_API_USAGE);
		}
	}

	/**
	 * Installs a custom channel factory so that the client may respond to
	 * channel open requests.
	 * 
	 * @param factory
	 *            the channel factory
	 * @throws SshException
	 */
	public void addChannelFactory(ChannelFactory factory) throws SshException {
		connection.addChannelFactory(factory);
	}

	public SshContext getContext() {
		return transport.transportContext;
	}

	/**
	 * Installs a global request handler so that the client may respond to
	 * global requests.
	 * 
	 * @param handler
	 *            the global request handler
	 * @throws SshException
	 */
	public void addRequestHandler(GlobalRequestHandler handler)
			throws SshException {

		// #ifdef DEBUG
		String requests = "";
		for (int i = 0; i < handler.supportedRequests().length; i++)
			requests += handler.supportedRequests()[i] + " ";
		EventLog.LogEvent(this, "Installing global request handler for "
				+ requests.trim());
		// #endif

		connection.addRequestHandler(handler);
	}

	/**
	 * Sends a global request to the remote side.
	 * 
	 * @param request
	 *            the global request
	 * @param wantreply
	 *            specifies whether the remote side should send a
	 *            success/failure message
	 * @return <code>true</code> if the request succeeded and wantreply=true,
	 *         otherwise <code>false</code>
	 * @throws SshException
	 */
	public boolean sendGlobalRequest(GlobalRequest request, boolean wantreply)
			throws SshException {
		verifyConnection(true);
		return connection.sendGlobalRequest(request, wantreply);
	}

	public String getRemoteIdentification() {
		return remoteIdentification;
	}

	void verifyConnection(boolean requireAuthentication) throws SshException {
		if (authentication == null || transport == null || connection == null) {
			throw new SshException("Not connected!", SshException.BAD_API_USAGE);
		}
		if (!transport.isConnected()) {
			throw new SshException("The connection has been terminated!",
					SshException.REMOTE_HOST_DISCONNECTED);
		}
		if (!authentication.isAuthenticated() && requireAuthentication) {
			throw new SshException("The connection is not authenticated!",
					SshException.BAD_API_USAGE);
		}

	}

	public String getUsername() {
		return username;
	}

	public SshClient duplicate() throws SshException {

		if ((username == null || auth == null)) {
			throw new SshException(
					"Cannot duplicate! The existing connection does not have a set of credentials",
					SshException.BAD_API_USAGE);
		}

		try {

			// #ifdef DEBUG
			EventLog.LogEvent(this, "Duplicating SSH client");
			// #endif

			SshClient duplicate = connector.connect(io.duplicate(), username,
					buffered, transport.transportContext);

			if (duplicate.authenticate(auth) != SshAuthentication.COMPLETE) {
				duplicate.disconnect();
				throw new SshException(
						"Duplication attempt failed to authenicate user!",
						SshException.INTERNAL_ERROR);
			}

			return duplicate;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.CONNECT_FAILED);
		}
	}

	class ForwardingRequestChannelFactory implements ChannelFactory {

		String[] types = new String[] {
				Ssh2ForwardingChannel.REMOTE_FORWARDING_CHANNEL, "x11" };

		public String[] supportedChannelTypes() {
			return types;
		}

		/**
		 * <p>
		 * Create an instance of an SSH channel. The new instance should be
		 * returned, if for any reason the channel cannot be created either
		 * because the channel is not supported or there are not enough
		 * resources an exception is thrown.
		 * </p>
		 * 
		 * @param channeltype
		 * @param requestdata
		 * @return an open channel
		 * @throws ChannelOpenException
		 */
		public Ssh2Channel createChannel(String channeltype, byte[] requestdata)
				throws SshException, ChannelOpenException {

			if (channeltype
					.equals(Ssh2ForwardingChannel.REMOTE_FORWARDING_CHANNEL)) {

				try {
					ByteArrayReader bar = new ByteArrayReader(requestdata);
					String address = bar.readString();
					int port = (int) bar.readInt();
					String originatorIP = bar.readString();
					int originatorPort = (int) bar.readInt();

					String key = address + ":" + String.valueOf(port);
					if (forwardingListeners.containsKey(key)) {
						ForwardingRequestListener listener = (ForwardingRequestListener) forwardingListeners
								.get(key);
						String destination = (String) forwardingDestinations
								.get(key);
						String hostToConnect = destination.substring(0,
								destination.indexOf(':'));
						int portToConnect = Integer.parseInt(destination
								.substring(destination.indexOf(':') + 1));

						// #ifdef DEBUG
						EventLog.LogEvent(this,
								"Creating remote forwarding channel from "
										+ address + ":" + port + " to "
										+ hostToConnect + ":" + portToConnect);
						// #endif

						// create connection from here to end point of tunnel,
						// then pass to new Ssh2ForwardingChannel
						Ssh2ForwardingChannel channel = new Ssh2ForwardingChannel(
								Ssh2ForwardingChannel.REMOTE_FORWARDING_CHANNEL,
								32768, 2097152, hostToConnect, portToConnect,
								address, port, originatorIP, originatorPort,
								listener.createConnection(hostToConnect,
										portToConnect));

						listener.initializeTunnel(channel);

						return channel;

					}
					throw new ChannelOpenException(
							"Forwarding had not previously been requested",
							ChannelOpenException.ADMINISTRATIVIVELY_PROHIBITED);
				} catch (IOException ex) {
					throw new ChannelOpenException(ex.getMessage(),
							ChannelOpenException.RESOURCE_SHORTAGE);
				} catch (SshException ex) {
					throw new ChannelOpenException(ex.getMessage(),
							ChannelOpenException.CONNECT_FAILED);
				}

			} else if (channeltype.equals("x11")) {

				if (!isXForwarding)
					throw new ChannelOpenException(
							"X Forwarding had not previously been requested",
							ChannelOpenException.ADMINISTRATIVIVELY_PROHIBITED);

				try {
					ByteArrayReader bar = new ByteArrayReader(requestdata);

					String originatorIP = bar.readString();
					int originatorPort = (int) bar.readInt();

					String display = connection.getContext().getX11Display();

					int i = display.indexOf(":");
					String targetAddr;
					int targetPort;
					int num = 0;
					int screen = 0;
					if (i != -1) {
						targetAddr = display.substring(0, i);
						display = display.substring(i + 1);
						i = display.indexOf('.');
						if (i > -1) {
							num = Integer.parseInt(display.substring(0, i));
							screen = Integer.parseInt(display.substring(i + 1));
						} else
							num = Integer.parseInt(display);

						targetPort = num;
					} else {
						targetAddr = display;
						targetPort = 6000;
					}

					if (targetPort <= 10) {
						targetPort += 6000;
					}

					// #ifdef DEBUG
					EventLog.LogEvent(this,
							"Creating X11 forwarding channel for display "
									+ targetAddr + ":" + screen);
					// #endif

					ForwardingRequestListener listener = connection
							.getContext().getX11RequestListener();

					Ssh2ForwardingChannel channel = new Ssh2ForwardingChannel(
							Ssh2ForwardingChannel.X11_FORWARDING_CHANNEL,
							32768, 32768, targetAddr, targetPort, targetAddr, // This
																				// will
																				// get
																				// set
																				// as
																				// the
																				// forwarding
																				// key
							screen, // This will get set as the forwarding key
							originatorIP, originatorPort,
							listener.createConnection(targetAddr, targetPort));

					listener.initializeTunnel(channel);

					return channel;

				} catch (Throwable ex) {
					throw new ChannelOpenException(ex.getMessage(),
							ChannelOpenException.CONNECT_FAILED);
				}
			}

			throw new ChannelOpenException(channeltype + " is not supported",
					ChannelOpenException.UNKNOWN_CHANNEL_TYPE);
		}
	}

	public int getChannelCount() {
		return connection.getChannelCount();
	}

	public int getVersion() {
		return 2;
	}

	public boolean isBuffered() {
		return buffered;
	}

	/**
	 * Returns the key exchange algorithm last used.
	 * 
	 * @return String
	 */
	public String getKeyExchangeInUse() {
		return (transport.keyExchange == null ? "none" : transport.keyExchange
				.getAlgorithm());
	}

	public SshKeyExchangeClient getKeyExchangeInstanceInUse() {
		return transport.keyExchange;
	}

	/**
	 * Returns the host key algorithm used in the last key exchange.
	 * 
	 * @return String
	 */
	public String getHostKeyInUse() {
		return (transport.hostkey == null ? "none" : transport.hostkey
				.getAlgorithm());
	}

	/**
	 * Get the cipher algorithm used to encrypt data sent to the server.
	 * 
	 * @return String
	 */
	public String getCipherInUseCS() {
		return (transport.encryption == null ? "none" : transport.encryption
				.getAlgorithm());
	}

	/**
	 * Get the cipher algorithm used to decrypt data received from the server.
	 * 
	 * @return String
	 */
	public String getCipherInUseSC() {
		return (transport.decryption == null ? "none" : transport.decryption
				.getAlgorithm());
	}

	/**
	 * Get the MAC algorithm used to verify data sent by the client.
	 * 
	 * @return String
	 */
	public String getMacInUseCS() {
		return (transport.outgoingMac == null ? "none" : transport.outgoingMac
				.getAlgorithm());
	}

	/**
	 * Get the MAC algorithm used to verify data sent by the server.
	 * 
	 * @return String
	 */
	public String getMacInUseSC() {
		return (transport.incomingMac == null ? "none" : transport.incomingMac
				.getAlgorithm());
	}

	/**
	 * Get the compression algorithm used to compress the clients outgoing data.
	 * 
	 * @return String
	 */
	public String getCompressionInUseCS() {
		return (transport.outgoingCompression == null ? "none"
				: transport.outgoingCompression.getAlgorithm());
	}

	/**
	 * Get the compression algorithm used to decompress the servers data.
	 * 
	 * @return String
	 */
	public String getCompressionInUseSC() {
		return (transport.incomingCompression == null ? "none"
				: transport.incomingCompression.getAlgorithm());
	}

	public String toString() {
		return "SSH2 "
				+ io.getHost()
				+ ":"
				+ io.getPort()
				+ " [kex="
				+ (transport.keyExchange == null ? "none"
						: transport.keyExchange.getAlgorithm())
				+ " hostkey="
				+ (transport.hostkey == null ? "none" : transport.hostkey
						.getAlgorithm())
				+ " client->server="
				+ (transport.encryption == null ? "none" : transport.encryption
						.getAlgorithm())
				+ ","
				+ (transport.outgoingMac == null ? "none"
						: transport.outgoingMac.getAlgorithm())
				+ ","
				+ (transport.outgoingCompression == null ? "none"
						: transport.outgoingCompression.getAlgorithm())
				+ " server->client="
				+ (transport.decryption == null ? "none" : transport.decryption
						.getAlgorithm())
				+ ","
				+ (transport.incomingMac == null ? "none"
						: transport.incomingMac.getAlgorithm())
				+ ","
				+ (transport.incomingCompression == null ? "none"
						: transport.incomingCompression.getAlgorithm()) + "]";
	}
}

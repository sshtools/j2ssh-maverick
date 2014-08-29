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
 * This interface defines the general contract for an SSH client that is
 * compatible for both the SSH1 and SSH2 protocols. This provides general
 * authentication and the opening of sessions. Further features may be available
 * depending upon the version of the SSH server and installed protocol support.
 * </p>
 * <p>
 * IMPORTANT NOTE: Caution should be applied when writing applications that are
 * to support both protocol versions; there are slight differences in the way
 * that SSH1 and SSH2 handle user sessions. SSH1 only supports a single session
 * channel on each connection where as SSH2 supports multiple sessions. When
 * calling <a href="#openSessionChannel()">openSessionChannel</a> on this
 * interface with an SSH2 connection, a new session is opened for each call and
 * the variable returned can be used independently of other sessions. For
 * example you can execute multiple commands on the remote host by simply
 * opening a session channel for each command. If the connection is SSH1 then
 * calling <a href="#openSessionChannel()">openSessionChannel</a> will result in
 * the same session being returned each time. Since you can only execute one
 * command, or start the users shell once on each session, code written to
 * handle the case of an SSH2 connection will fail.
 * </p>
 * 
 * @author Lee David Painter
 */
public interface SshClient extends Client {

	/**
	 * Connect to an SSH server.
	 * 
	 * @param transport
	 *            the transport layer
	 * @param context
	 *            an SSH context
	 * @param username
	 *            the users name
	 * @param localIdentification
	 *            the local identification string
	 * @param remoteIdentification
	 *            the remotes identification string
	 * @param buffered
	 *            should the connection be buffered (threaded)
	 * @throws SshException
	 */
	void connect(SshTransport transport, SshContext context,
			SshConnector connector, String username,
			String localIdentification, String remoteIdentification,
			boolean buffered) throws SshException;

	/**
	 * <p>
	 * Authenticate the user. Once connected call to authenticate the user. When
	 * a connection is made no other operations can be performed until the user
	 * has been authenticated.
	 * </p>
	 * 
	 * @param auth
	 *            the authentication mechanism.
	 * @return one of the constants defined in <a
	 *         href="SshAuthentication.html">SshAuthentication</a> which
	 *         indicates the state of the current authentication process.
	 * @throws SshException
	 */
	public int authenticate(SshAuthentication auth) throws SshException;

	/**
	 * <p>
	 * Open a session on the remote computer. This can only be called once the
	 * user has been authenticated. The session returned is uninitialized and
	 * will be opened when either a command is executed or the users shell has
	 * been started.
	 * </p>
	 * 
	 * @return an uninitialized session instance.
	 * @throws SshException
	 */
	public SshSession openSessionChannel() throws SshException,
			ChannelOpenException;

	/**
	 * <p>
	 * Open a session on the remote computer. This can only be called once the
	 * user has been authenticated. The session returned is uninitialized and
	 * will be opened when either a command is executed or the users shell has
	 * been started.
	 * </p>
	 * 
	 * @param listener
	 *            an event listener to add before opening
	 * @return an uninitialized session instance.
	 * @throws SshException
	 */
	public SshSession openSessionChannel(ChannelEventListener listener)
			throws SshException, ChannelOpenException;

	/**
	 * <p>
	 * Open a TCPIP forwarding channel to the remote computer. If successful the
	 * remote computer will open a socket to the host/port specified and return
	 * a channel which can be used to forward TCPIP data from the local computer
	 * to the remotley connected socket.
	 * </p>
	 * 
	 * <p>
	 * It should be noted that this is a low level API method and it does not
	 * connect the transport to the channel as this would require some
	 * threading. The transport is passed here so that it can be attached to the
	 * <a href="SshTunnel.html"> SshTunnel</a> that is returned. If you want to
	 * have the API automatically connect the channel to the transport you
	 * should use the <a
	 * href="../../sshtools/net/ForwardingClient.html">ForwardingClient</a>
	 * which provides management of forwarding connections and threads.
	 * </p>
	 * 
	 * @param hostname
	 *            the host to connect to
	 * @param port
	 *            the port to connect to
	 * @param originatingHost
	 *            the originating host (informational only)
	 * @param originatingPort
	 *            the originating port (informational only)
	 * @param transport
	 * @param listener
	 *            an event listener that will be added to the channel before
	 *            opening.
	 * @return SshTunnel
	 * @throws SshException
	 */
	public SshTunnel openForwardingChannel(String hostname, int port,
			String listeningAddress, int listeningPort, String originatingHost,
			int originatingPort, SshTransport transport,
			ChannelEventListener listener) throws SshException,
			ChannelOpenException;

	/**
	 * Open up an SSH client from the remote machine to another remote server.
	 * This method is useful if your firewall only forwards SSH connections to a
	 * single machine. Once connected to the exposed machine you can call this
	 * to obtain an {@link SshClient} instance to any other machine on the same
	 * network.
	 * 
	 * @param hostname
	 *            the name of the remote host
	 * @param port
	 *            the port of the remote host
	 * @param username
	 *            the name of the user on the remote host
	 * @param con
	 *            an {@link SshConnector} instance that will be used to connect
	 *            the client. This does not have to be the same instance that
	 *            created this client.
	 * @return SshClient
	 * @throws SshException
	 * @throws ChannelOpenException
	 */
	public SshClient openRemoteClient(String hostname, int port,
			String username, SshConnector con) throws SshException,
			ChannelOpenException;

	/**
	 * Open up an SSH client from the remote machine to another remote server.
	 * This method is useful if your firewall only forwards SSH connections to a
	 * single machine. Once connected to the exposed machine you can call this
	 * to obtain an {@link SshClient} instance to any other machine on the same
	 * network.
	 * 
	 * @param hostname
	 *            the name of the remote host
	 * @param port
	 *            the port of the remote host
	 * @param username
	 *            the name of the user on the remote host
	 * @return SshClient
	 * @throws SshException
	 * @throws ChannelOpenException
	 */
	public SshClient openRemoteClient(String hostname, int port, String username)
			throws SshException, ChannelOpenException;

	/**
	 * Requests that the remote computer accepts socket connections and forward
	 * them to the local computer. The <a href="ForwardingRequestListener.html">
	 * ForwardingRequestListener</a> provides callback methods to create the
	 * connections and to initialize the tunnel.
	 * 
	 * 
	 * 
	 * @param bindAddress
	 *            the address that the remote computer should listen on
	 * @param bindPort
	 *            the port that the remote computer should listen on
	 * @param hostToConnect
	 *            the host to connect when a connection is established
	 * @param portToConnect
	 *            the port to connect when a connection is established
	 * @param listener
	 *            a callback interface
	 * @return boolean
	 * @throws SshException
	 */
	public boolean requestRemoteForwarding(String bindAddress, int bindPort,
			String hostToConnect, int portToConnect,
			ForwardingRequestListener listener) throws SshException;

	/**
	 * Cancel a forwarding request.
	 * 
	 * @param bindAddress
	 *            the address that the remote computer is listening on.
	 * @param bindPort
	 *            the port that the remote computer is listening on.
	 * @return <tt>true</tt> if the forwarding was cancelled, otherwise
	 *         <tt>false</tt>
	 * @throws SshException
	 */
	public boolean cancelRemoteForwarding(String bindAddress, int bindPort)
			throws SshException;

	/**
	 * Disconnect from the remote computer.
	 */
	public void disconnect();

	/**
	 * Evaluate whether the user has been authenticated. If the server does not
	 * require the user to authenticate; this may return <code>true</code>
	 * immediatley after connection. No other operations can be perform until
	 * the user has been authenticated.
	 * 
	 * @return <code>true</code> if the connection is authenticated, otherwise
	 *         <code>false</code>
	 */
	public boolean isAuthenticated();

	/**
	 * Evaluate whether the connection is still alive.
	 * 
	 * @return <code>true</code> if connected, otherwise <code>false</code>
	 */
	public boolean isConnected();

	/**
	 * Returns the identification string supplied by the server during protocol
	 * negotiation.
	 * 
	 * @return the servers identification String, for example
	 *         "SSH-1.99-OpenSSH_3.7p"
	 */
	public String getRemoteIdentification();

	/**
	 * Return the username used for this connection
	 * 
	 * @return the users name
	 */
	public String getUsername();

	/**
	 * Create an identical version of an SshClient using cached authentication
	 * information and the SshTransport duplicate method.
	 * 
	 * @return SshClient
	 * @throws SshException
	 */
	public SshClient duplicate() throws SshException;

	/**
	 * Get the context that created this client.
	 * 
	 * @return SshContext
	 */
	public SshContext getContext();

	/**
	 * Get the number of active channels.
	 * 
	 * @return int
	 */
	public int getChannelCount();

	/**
	 * Returns the version for this client. The value will be either 1 for SSH1
	 * or 2 for SSH2.
	 * 
	 * @return int
	 */
	public int getVersion();

	/**
	 * Identifies whether this client is in buffered mode
	 * 
	 * @return boolean
	 */
	public boolean isBuffered();
}

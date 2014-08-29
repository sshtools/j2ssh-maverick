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
 * This interface is required when a request for remote port forwarding is made.
 * The methods enable you to establish a connection to the host and initialize
 * the forwarding channel before it is opened.
 * 
 * @author Lee David Painter
 */
public interface ForwardingRequestListener {

	/**
	 * Create a connection to the specified host. When requesting remote
	 * forwarding you specify the host and port to which incoming connections
	 * are bound. This method should create a connection to the host and return
	 * an <a href="SshTransport.html">SshTransport</a> implementation.
	 * 
	 * @see com.sshtools.ssh.SshTransport
	 * 
	 * @param hostToConnect
	 * @param portToConnect
	 * @return SshTransport
	 * @throws SshException
	 */
	public SshTransport createConnection(String hostToConnect, int portToConnect)
			throws SshException;

	/**
	 * Called once a connection has been established and a forwarding channel is
	 * about to be opened. Please note that the channel IS NOT open when this
	 * method is called and therefore cannot be used to start transfering data.
	 * This provides you with the ability to configure the channel, for instance
	 * by adding a <a href="ChannelEventListener.html">ChannelEventListener</a>
	 * to activate the channel once it has been opened. <blockquote>
	 * 
	 * <pre>
	 * public void initializeTunnel(SshTunnel tunnel) {
	 * 	tunnel.addChannelEventListener(new ChannelAdapter() {
	 * 		public void channelOpened(SshChannel channel) {
	 * 
	 * 			// Cast the channel into a tunnel
	 * 			SshTunnel tunnel = (SshTunnel) channel;
	 * 
	 * 			// Create a pair of IOStreamConnectors to transfer the data
	 * 			IOStreamConnector tx = new IOStreamConnector();
	 * 			tx.connect(tunnel.getInputStream(), tunnel.getTransport()
	 * 					.getOutputStream());
	 * 
	 * 			IOStreamConnector rx = new IOStreamConnector();
	 * 			tx.connect(tunnel.getTransport().getInputStream(),
	 * 					tunnel.getOutputStream());
	 * 		}
	 * 	});
	 * }
	 * </pre>
	 * 
	 * </blockquote>
	 * 
	 * @param tunnel
	 */
	public void initializeTunnel(SshTunnel tunnel);
}

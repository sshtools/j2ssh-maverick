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

package com.sshtools.net;

import java.net.SocketAddress;

import com.sshtools.ssh.SshTunnel;

/**
 * An event listener for receiving notification of forwarding events.
 * @author Lee David Painter
 */
public interface ForwardingClientListener {

  /** Constant used to specify whether the event relates to a local forwarding **/
  public static final int LOCAL_FORWARDING = 1;
  /** Constant used to specify whether the event relates to a remote forwarding **/
  public static final int REMOTE_FORWARDING = 2;
  /** Constant used to specify whether the event relates to an X11 forwarding **/
  public static final int X11_FORWARDING = 3;

  /**
   * The forwarding has been started and any connections made to the listening
   * address (which is specified by the key in the format 'ipaddress:port') will
   * be forwarded over the connection to the host and port specified.
   *
   * @param type
   * @param key
   * @param host
   * @param port
   */
  public void forwardingStarted(int type, String key, String host, int port);

  /**
   * The forwarding identifed by the key has been stopped.
   * @param type
   * @param key
   * @param host
   * @param port
   */
  public void forwardingStopped(int type, String key, String host, int port);

  /**
   * A forwarding channel failed to open.
   * @param type
   * @param key
   * @param host
   * @param port
   * @param isConnected
   * @param t
   */
  public void channelFailure(int type,
                             String key,
                             String host,
                             int port,
                             boolean isConnected,
                             Throwable t);

  /**
   * A forwarding channel has been opened.
   * @param type
   * @param key
   * @param tunnel
   */
  public void channelOpened(int type, String key, SshTunnel tunnel);

  /**
   * A forwarding channel has been closed.
   * @param type
   * @param key
   * @param tunnel
   */
  public void channelClosed(int type, String key, SshTunnel tunnel);
  
  
  /**
   * Accept a remote forwarding based on the remote socket address?
   * @param remoteAddress
   * @param host
   * @param port
   * @return
   */
  public boolean acceptLocalForwarding(SocketAddress remoteAddress, String host, int port);
}

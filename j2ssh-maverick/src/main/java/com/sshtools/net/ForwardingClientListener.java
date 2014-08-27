
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

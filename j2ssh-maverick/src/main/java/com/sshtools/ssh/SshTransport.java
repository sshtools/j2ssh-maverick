
package com.sshtools.ssh;

import java.io.IOException;

/**
 *
 * <p>Simple interface wrapper for transport layer communication.
 * An SSH connection requires a transport layer for communication and this
 * interface defines the general contract. Typically SSH will execute over
     * a TCPIP Socket however the use of this interface allows any type of transport
 * that can expose a set of I/O streams. In the simplest form this interface
 * will be implemented for a Socket as follows:
 * <a name="SocketTransport"></a>
 * <blockquote><pre>
 * import java.net.Socket;
 * import java.io.*;
 *
 * public class SocketTransport extends Socket implements SshTransport {
 *   public SocketProvider(String host, int port) throws IOException {
 *     super(host, port);
 *   }
 *   public String getConnectedHost() {
 *      return getInetAddress().getHostName();
 *   }
 *
 *   ** The close, getInputStream and getOutputStream methods are exposed **
 *   ** directly by the Socket.                                           **
 * </blockquote></pre></p>
 * @author Lee David Painter
 */
public interface SshTransport extends SshIO {


  /**
   * Get the name of the connected host.
   * @return the name of the connected host
   */
  public String getHost();

  /**
   * Get the port of this connection
   * @return int
   */
  public int getPort();

  /**
   * Create a new copy of this transport and connect to the
   * same host:port combination. This is used by the SshClient
   * to duplicate a client connection.
   * @return SshTransport
   * @throws SshException
   */
  public SshTransport duplicate() throws IOException;

}

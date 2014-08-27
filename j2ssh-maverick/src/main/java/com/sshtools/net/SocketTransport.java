
package com.sshtools.net;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.Socket;

import com.sshtools.ssh.SocketTimeoutSupport;
import com.sshtools.ssh.SshTransport;

/**
 * Extends a Socket to provide an
 * <a href="../../maverick/ssh/SshTransport.html">SshTransport</a> suitable
 * for use in making connections using the <a href="../../maverick/ssh/SshConnector.html">SshConnector</a>.
 *
 * @author Lee David Painter
 */
public class SocketTransport
    extends Socket
    implements SshTransport, SocketTimeoutSupport {
  
  String hostname;
	
  /**
   * Connect the socket.
   * @param hostname
   * @param port
   * @throws IOException
   */
  public SocketTransport(String hostname, int port) throws IOException {
    super(hostname, port);

    this.hostname = hostname;

    /**
     * The setSendBufferSize and setReceiveBufferSize methods are 1.2
     * , so we use reflection so that if we are in 1.1 the code doesn't fall over.
     */
    try {
        Method m = Socket.class.getMethod("setSendBufferSize", new Class[] { int.class });
        m.invoke(this, new Object[] { new Integer(65535)});
    } catch(Throwable t) {
    	//this will error in 1.1 as it is a 1.2 method, so ignore.
    }

    try {
        Method m = Socket.class.getMethod("setReceiveBufferSize", new Class[] { int.class });
        m.invoke(this, new Object[] { new Integer(65535)});
    } catch(Throwable t) {
    	//this will error in 1.1 as it is a 1.2 method, so ignore.
    }

  }

  /**
   * Get the hostname of the connected host.
   */
  public String getHost() {
    return hostname;
  }

  public SshTransport duplicate() throws IOException {
      return new SocketTransport(getHost(), getPort());
  }
}

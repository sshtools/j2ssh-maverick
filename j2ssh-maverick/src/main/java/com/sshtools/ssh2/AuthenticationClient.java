
package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.SshAuthentication;
import com.sshtools.ssh.SshException;

/**
 *
 * <p>Base interface for all SSH authentication mechanisms. Each authentication
 * mechanism must conform to this interface which is called by the
 * <a href="AuthenticationProtocol.html">AuthenticationProtocol</a> after the
 * user invokes the authenticate method. Using the methods of the
 * <a href="AuthenticationProtocol.html">AuthenticationProtocol</a> the
     * implementation must read and send messages are required by the authentication
 * specification. When the server return's either a SSH_MSG_USERAUTH_SUCCESS
 * or SSH_MSG_USERAUTH_FAILURE the readMessage method will throw
 * <a href="AuthenticationResult.html">AuthenticationResult</a> and return
     * back to the <a href="AuthenticationProtocol.html">AuthenticationProtocol</a>.
 * This throwable class can also be thrown by the implementor from within
 * the mechanisms implementation, for instance if the user cancelled the
 * authentication.</p>
 *
 * @author Lee David Painter
 */
public interface AuthenticationClient
    extends SshAuthentication {

  /**
   * Perform the authentication according to the specification. The expected
   * result of this method is for the caller to catch an
   * <a href="AuthenticationResult.html">AuthenticationResult</a>. If the
   * method returns without throwing this then the caller will attempt to
   * read the next message available expecting it to be either a
   * SSH_MSG_USERAUTH_SUCCESS or SSH_MSG_USERAUTH_FAILURE.
   *
   * @param authentication
   * @param servicename
   * @throws IOException
   * @throws AuthenticationResult
   */
  public void authenticate(AuthenticationProtocol authentication,
                           String servicename) throws SshException,
      AuthenticationResult;
}

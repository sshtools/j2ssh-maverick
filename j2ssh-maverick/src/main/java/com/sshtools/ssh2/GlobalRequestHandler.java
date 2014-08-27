
package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.SshException;

/**
 * <p>There are several kinds of requests that affect the state of the remote end "globally",
 * independent of any channels, this interface defines the contract for handling such global
 * requests.
 * </p>
 *
 * @author Lee David Painter
 */
public interface GlobalRequestHandler {

  /**
   * Return the supported request types.
   * @return an array of Strings containing the supported request types.
   */
  public String[] supportedRequests();

  /**
   * Called when a supported global request has been recieved.
   * @param request
   * @return <code>true</code> if the request succeeded, otherwise <code>false</code>
   * @throws IOException
   */
  public boolean processGlobalRequest(GlobalRequest request) throws SshException;
}

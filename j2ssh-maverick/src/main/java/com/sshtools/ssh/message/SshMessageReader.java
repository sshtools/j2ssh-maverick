
package com.sshtools.ssh.message;

import com.sshtools.ssh.SshException;
/**
 * @author Lee David Painter
 */
public interface SshMessageReader {
  public byte[] nextMessage() throws SshException;

  public boolean isConnected();
}

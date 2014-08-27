
package com.sshtools.ssh.components;

import java.io.IOException;

import com.sshtools.ssh.SshException;

/**
 *  Interface for SSH supported private keys.
 *
 *  @author Lee David Painter
 */
public interface SshPrivateKey {

  /**
   * Create a signature from the data.
   * @param data
   * @return byte[]
   * @throws SshException
   */
  public byte[] sign(byte[] data) throws IOException;

  public String getAlgorithm();
}

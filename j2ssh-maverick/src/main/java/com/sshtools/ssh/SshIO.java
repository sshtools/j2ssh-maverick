
package com.sshtools.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * <p>Base interface for all SSH related IO interfaces.</p>
 *
 * @author Lee David Painter
 */
public interface SshIO {

  /**
   * Get an InputStream to read incoming channel data.
   * @return the channels InputStream
   * @throws IOException
   */
  public InputStream getInputStream() throws IOException;

  /**
   * Get an OutputStream to write outgoing channel data.
   * @return the channels OutputStream
   * @throws IOException
   */
  public OutputStream getOutputStream() throws IOException;

  /**
   * Close the channel.
   * @throws SshIOException
   */
  public void close() throws IOException;

}


package com.sshtools.sftp;

/**
 * <p>Exception thrown when a file transfer is cancelled.</p>
 *
 * @author Lee David Painter
 */
public class TransferCancelledException
    extends Exception {

	private static final long serialVersionUID = 1L;

/**
   * Creates a new TransferCancelledException object.
   */
  public TransferCancelledException() {
    super();
  }
}

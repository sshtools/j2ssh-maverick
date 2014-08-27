
package com.sshtools.publickey;

/**
 * Exception thrown by the {@link PublicKeySubsystem} when errors occur in
 * listing, adding or removing keys.
 *
 * @author Lee David Painter
 */
public class PublicKeySubsystemException extends Exception {

  private static final long serialVersionUID = 1L;
  static final int SUCCESS = 0;
  public static final int ACCESS_DENIED = 1;
  public static final int STORAGE_EXCEEDED = 2;
  public static final int REQUEST_NOT_SUPPPORTED = 3;
  public static final int KEY_NOT_FOUND = 4;
  public static final int KEY_NOT_SUPPORTED = 5;
  public static final int GENERAL_FAILURE = 6;

  int status;

  public PublicKeySubsystemException(int status, String desc) {
    super(desc);
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

}

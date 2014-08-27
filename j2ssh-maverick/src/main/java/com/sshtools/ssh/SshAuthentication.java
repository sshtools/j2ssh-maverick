
package com.sshtools.ssh;

/**
 * <p>The base interface for all SSH authentication mechanisms and authentication result constants.</p>
 *
 * @author Lee David Painter
 */
public interface SshAuthentication {

  /** The authentication completed **/
  public static final int COMPLETE = 1;
  /** The authentication failed **/
  public static final int FAILED = 2;
  /** The authentication succeeded but further authentication is required **/
  public static final int FURTHER_AUTHENTICATION_REQUIRED = 3;
  /** The authentication was cancelled by the user  */
  public static final int CANCELLED = 4;
  /** The public key provided is acceptable for authentication **/
  public static final int PUBLIC_KEY_ACCEPTABLE = 5;

  /**
   * Set the username for this authentication attempt.
   * @param username
   */
  public void setUsername(String username);

  /**
   * Get the username for this authentication attempt.
   * @return the username used.
   */
  public String getUsername();

  /**
   * The SSH authentication method name
   * @return String
   */
  public String getMethod();
}

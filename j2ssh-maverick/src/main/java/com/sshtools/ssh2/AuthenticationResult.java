
package com.sshtools.ssh2;

/**
 * <p>Throwable class used by the <a href="AuthenticationProtocol.html">
 * AuthenticationProtocol</a> to indicate that a authentication request
 * has either been completed, failed or cancelled.</p>
 *
 * @author Lee David Painter
 */
public class AuthenticationResult
    extends Throwable {

	private static final long serialVersionUID = 1L;
	int result;
	String auths;

  /**
   * Construct an AuthenticationResult
   * @param result
   */
  public AuthenticationResult(int result) {
    this.result = result;
  }

  /**
   * Construct an AuthenticationResult
   * @param result
   * @param auths
   */
  public AuthenticationResult(int result, String auths) {
    this.result = result;
    this.auths = auths;
  }

  /**
   * Get the result of this authentication.
   * @return one of the constants defined above
   */
  public int getResult() {
    return result;
  }

  /**
   * Get the authentication methods that can be used.
   * @return a comma delimited list of authentication methods, for example
   *         "publickey,password"
   */
  public String getAuthenticationMethods() {
    return auths;
  }

}
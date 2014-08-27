/**
 * Copyright 2003-2014 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */

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
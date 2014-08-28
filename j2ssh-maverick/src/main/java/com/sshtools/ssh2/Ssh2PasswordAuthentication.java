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

import java.io.IOException;

import com.sshtools.ssh.PasswordAuthentication;
import com.sshtools.ssh.SshAuthentication;
import com.sshtools.ssh.SshException;
import com.sshtools.util.ByteArrayWriter;

/**
 * <p>Implements Password authentication as defined in the SSH Authenticaiton
 * Protocol. To use password authentication first construct an instance and
 * set the username and password fields.
 * <blockquote><pre>
 * PasswordAuthentication pwd = new PasswordAuthentication();
 *
 * pwd.setUsername("username");
 * pwd.setPassword("password");
 *
 * int result = ssh.authenticate(pwd);
 * </pre></blockquote>
 * When the authentication returns the result should be evaluated. If the
 * authentication has completed no further processing is required, however
 * if the result is failed you should check the password change flag to
 * determine if the attempt failed because the user is required to change
     * their password. If this is required set the new password on the instance using
 * <a href="#setNewPassword(String)">setNewPassword</a> and call the
     * authentication procedure again. If the authenticaiton fails again the password
 * may not be acceptable.
 * <blockquote><pre>
 * if(result==SshAuthentication.FAILED) {
 *   if(pwd.requiresPasswordChange()) {
 *      pwd.setNewPassword("foo");
 *
 *      // Perform authentication again
 *      result = ssh.authenticate(pwd);
 *   }
 * }
 *
 * </pre></blockquote></p>
 * @author Lee David Painter
 */
public class Ssh2PasswordAuthentication
    extends PasswordAuthentication
    implements AuthenticationClient {

  String newpassword;
  boolean passwordChangeRequired = false;

  final static int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

  /**
   * Construct the method
   */
  public Ssh2PasswordAuthentication() {
  }

  /**
   * After performing an initial authentication attempt a flag may be
   * set to indicate that a password change is required. Use this method
   * to set the new password and retry the authentication attempt.
   * @param newpassword
   */
  public void setNewPassword(String newpassword) {
    this.newpassword = newpassword;
  }

  /**
   * Indicates whether the users password requires changing. This will always
   * return <code>false</code> until after an initial authentication attempt.
   * Then it MAY be <code>true</code> so should always be checked upon a failed
   * attempt.
   * @return <code>true</code> if the user must change their password otherwise
   *         <code>false</code>.
   */
  public boolean requiresPasswordChange() {
    return passwordChangeRequired;
  }

  /**
   * Implementation of the authentication method.
   * @param authentication
   * @param servicename
   * @throws IOException
   * @throws AuthenticationResult
   */
  public void authenticate(AuthenticationProtocol authentication,
                           String servicename) throws SshException,
      AuthenticationResult {

    try {
      if(getUsername() == null || getPassword() == null) {
        throw new SshException("Username or password not set!",
                               SshException.BAD_API_USAGE);
      }

      if(passwordChangeRequired && newpassword == null) {
        throw new SshException("You must set a new password!",
                               SshException.BAD_API_USAGE);
      }

      ByteArrayWriter msg = new ByteArrayWriter();
      
      try {
	      msg.writeBoolean(passwordChangeRequired);
	      msg.writeString(getPassword());
	      if(passwordChangeRequired) {
	        msg.writeString(newpassword);
	
	      }
	      authentication.sendRequest(getUsername(),
	                                 servicename,
	                                 "password",
	                                 msg.toByteArray());
      } finally {
		try {
			msg.close();
		} catch (IOException e) {
		}
    }
      // We need to read the response since we may have password change.
      byte[] response = authentication.readMessage();

      if(response[0] != SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
        authentication.transport.disconnect(TransportProtocol.PROTOCOL_ERROR,
                                            "Unexpected message received");
        throw new SshException(
           "Unexpected response from Authentication Protocol",
           SshException.PROTOCOL_VIOLATION);
      }

      passwordChangeRequired = true;
      throw new AuthenticationResult(SshAuthentication.FAILED);
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }

}

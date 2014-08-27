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

package com.sshtools.ssh;

import com.sshtools.ssh.components.SshPrivateKey;
import com.sshtools.ssh.components.SshPublicKey;

/**
 *
 * <p>Public key based authentication implementation. Public-key authentication uses public-key
 * cryptography to verify the client's identity. To access an account on an SSH server machine, the
 * client proves that it possesses a secret key. A key is authorized if its public component is
 * contained in the accounts authorization file (typically ~/.ssh/authorized_keys).
 *
 * <p>This class implements a basic publickey <a href="SshAuthentication.html">SshAuthentication</a> that can be
 * passed into the <a href="SshClient.html">SshClient</a> to authenticate. As a username is required to
 * establish a connection it is not required that it be set on the authentication object, however if you
 * wish to change the username you can do so (this may not be allowed by some server
 * implementations).</p>
 *
 * <p>First you need to load a public/private key pair; a set of utility classes based on the
 * SSHTools public key formats is available in the <a href="../../sshtools/publickey/package-summary.html">com.sshtools.publickey</a>
 * package. </p>
 * <blockquote><pre>
 * FileInputStream in = new FileInputStream("someprivatekey");
 * ByteArrayOutputStream out = new ByteArrayOutputStream();
 * int read;
 * while((read = in.read()) > -1)
 *   out.write(read);
 *
 * in.close();
 *
 * SshPrivateKeyFile pkf = SshPrivateKeyFileFactory.parse(out.toByteArray());
 * SshKeyPair pair = pkf.toKeyPair("mypassphrase");
 *
 * PublicKeyAuthentication pk = new PublicKeyAuthentication();
 * pk.setPrivateKey(pair.getPrivateKey());
 * pk.setPublicKey(pair.getPublicKey());
 *
 * if(ssh.authenticate(pk)==SshAuthentication.COMPLETE)
 *  	System.out.println("Authentication completed");
 * </pre></blockquote>
 *
 * @author Lee David Painter
 */
public class PublicKeyAuthentication
    implements SshAuthentication {

  String username;
  SshPrivateKey privatekey;
  SshPublicKey publickey;
  boolean authenticating = true;

  /* (non-Javadoc)
   * @see com.maverick.ssh.SshAuthentication#setUsername(java.lang.String)
   */
  public void setUsername(String username) {
    this.username = username;
  }

  /* (non-Javadoc)
   * @see com.maverick.ssh.SshAuthentication#getUsername()
   */
  public String getUsername() {
    return username;
  }

  /**
   * Set the private key for this authentication.
   * @param privatekey
   */
  public void setPrivateKey(SshPrivateKey privatekey) {
    this.privatekey = privatekey;
  }

  public String getMethod() {
      return "publickey";
  }

  /**
   * Get the private key for this authentication.
   * @return SshPrivateKey
   */
  public SshPrivateKey getPrivateKey() {
    return privatekey;
  }

  /**
   * Set the public key for this authentication.
   * @param publickey
   */
  public void setPublicKey(SshPublicKey publickey) {
    this.publickey = publickey;
  }

  /**
   * Get the public key for this authentication.
   * @return SshPublicKey
   */
  public SshPublicKey getPublicKey() {
    return publickey;
  }

  /**
   * If <tt>true</tt> the authentication will proceed as normal and the result will either
   * be a success or failure. If <tt>false</tt> the authentication result will be either
   * PUBLIC_KEY_ACCEPTABLE or a failure. If the result returned is PUBLIC_KEY_ACCEPTABLE the
   * authentication can be completed by setting this flag to <tt>true</tt> and re-authenticating
   * with the SshClient.
   * @param authenticating
   */
  public void setAuthenticating(boolean authenticating) {
    this.authenticating = authenticating;
  }

  /**
   * Is the authentication attempt actually going to perform an authentication or
   * are we simply just checking the suitability of a public key.
   * @return boolean
   */
  public boolean isAuthenticating() {
    return authenticating;
  }


}

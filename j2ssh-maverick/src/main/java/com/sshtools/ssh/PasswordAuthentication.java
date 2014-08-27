
package com.sshtools.ssh;

/**
 * <p>Basic password authentication class used for SSH password authentication.
 * Once a connection has been established to an SSH server the user is normally
 * required to authenticate themselves. This class implements a basic password
 * <a href="SshAuthentication.html">SshAuthentication</a> that can be passed into the
 * <a href="SshClient.html">SshClient</a> to authenticate. As a username is required to
 * establish a connection it is not required that it be set on the password object, however if you
 * wish to change the username you can do so (this may not be allowed by some server
 * implementations).</p>
 *
 * <p>Use password authentication as follows:
 * <blockquote><pre>
 * SshConnector con = SshConnector.getInstance();
 * SshClient ssh = con.connect(new SocketTransport("beagle2.mars.net", 22), "martianx");
 *
 * PasswordAuthentication pwd = new PasswordAuthentication();
 * pwd.setPassword("likeidgivethataway!");
 *
 * if(!ssh.isAuthenticated()) {
 *   if(ssh.authenticate(pwd)==SshAuthentication.COMPLETE) {
 *     // Transfer some files or do something else interesting
 *   }
 * }
 * </pre></blockquote></p>
 * <p>It is recommended that in situations where you may be connecting to
 * an SSH2 server, that the <a href="../ssh2/Ssh2PasswordAuthentication.html">Ssh2PasswordAuthentication</a>
 * subclass is used instead. This extends the basic functionality provided here by supporting the changing of
 * the users password.</p>
 *
 * @see com.sshtools.ssh2.Ssh2PasswordAuthentication
 * @author Lee David Painter
 */
public class PasswordAuthentication
    implements SshAuthentication {

  String password;
  String username;

  /**
   * Set the password.
   * @param password
   */
  public void setPassword(String password) {
    this.password = password;
  }

  /**
   * Get the password.
   * @return the password
   */
  public String getPassword() {
    return password;
  }

  public String getMethod() {
      return "password";
  }

  /**
   * Set the username.
   */
  public void setUsername(String username) {
    this.username = username;
  }

  /**
   * Get the username.
   */
  public String getUsername() {
    return username;
  }
}

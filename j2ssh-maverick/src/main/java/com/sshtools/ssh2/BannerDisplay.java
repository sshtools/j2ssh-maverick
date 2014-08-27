
package com.sshtools.ssh2;


/**
 *
 * <p>Callback interface to display authentication banner messages.</p>
 *
 * <p>In some jurisdictions sending a warning message before
 * authentication may be relevant for getting legal protection.  Many
 * UNIX machines, for example, normally display text from
 * `/etc/issue', or use "tcp wrappers" or similar software to display
 * a banner before issuing a login prompt.</p>
 *
 * <p>Implement this interface to show the authentication banner message.
 * The method should display the message and should not return until the user
 * accepts the message</p>
 *
 * <p>To configure a banner display you must setup the <a href="Ssh2Context">Ssh2Context</a>
 * on a <a href="../ssh/SshConnector">SshConnector</a> instance using the following code:
 * <blockquote><pre>
 * SshConnector con = SshConnector.getInstance();
 *
 * BannerDisplay display = new BannerDisplay() {
 * 	public void displayBanner(String message) {
 * 		System.out.println(message);
 * 		System.in.read();
 *      }
 * };
 * Ssh2Context context = (Ssh2Context)con.getContext(SshConnector.SSH2);
 * context.setBannerDisplay(display);
 * </pre></blockquote>
 * @author Lee David Painter
 */
public interface BannerDisplay {
  /**
   * Called when a banner message is received.
   * @param message the message to display.
   */
  public void displayBanner(String message);
}
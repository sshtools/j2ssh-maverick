
package com.sshtools.ssh2;

/**
 *
 * Callback interface used by the <a href="KBIAuthentication.html">KBIAuthentication</a>
 * authentication mechanism.
 *
 * @author $author$
 */
public interface KBIRequestHandler {
  /**
   * Called by the <em>keyboard-interactive</em> authentication mechanism when
       * the server requests information from the user. Each prompt should be displayed
   * to the user with their response recorded within the prompt object.
   *
   * @param name
   * @param instruction
   * @param prompts
   * @return <em>true</em> if the user entered the prompts, or <em>false</em> if the
   * user cancelled the authentication attempt. 
   */
  public boolean showPrompts(String name, String instruction, KBIPrompt[] prompts);
}

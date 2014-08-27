
package com.sshtools.ssh2;

import java.io.IOException;

import com.sshtools.ssh.SshAuthentication;
import com.sshtools.ssh.SshException;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
     * <p><em>keyboard-interactive</em> authentication implementation as specified in
 * draft-ietf-secsh-auth-kbdinteract-04.txt. Keyboard interactive provides
 * a challenge-response type authentication which allows clients to
 * support authentication mechanisms where the actual specification is not known.</p>
 *
 * <p>The process works by the client first requesting the keyboard-interactive method; the
 * server then responds with any number of prompts to which the user must provide an
 * answer. This is acheived through the use of the <a href="KBIRequestHandler.html">
 * KBIRequestHandler</a> interface.</p>
 * <blockquote><pre>
 * KBIAuthentication kbi = new KBIAuthentication();
 *
 * kbi.setKBIRequestHandler(new KBIRequestHandler() {
 *  	public void showPrompts(String name, String instruction, KBIPrompt[] prompts) {
 * 					try {
 * 						System.out.println(name);
 * 						System.out.println(instruction);
 *						for(int i=0;i&ltprompts.length;i++) {
 *							System.out.print(prompts[i].getPrompt());
 *							prompts[i].setResponse(reader.readLine());
 *						}
 *					} catch (IOException e) {
 *						e.printStackTrace();
 *					}
 *				}
 *			});
 *
 *	ssh.authenticate(kbi);
 * </pre></blockquote>
 * <p>Special care should be taken to check the echo flag of the <a href="KBIPrompt.hmtl">KBIPrompt</a>
 * if set to <tt>false</tt> the user reponse entered by the user should not be echo'd back to the
 * screen, for example in the process of entering a password.</p>
 *
 * @author Lee David Painter
 */
public class KBIAuthentication
    implements AuthenticationClient {

  String username;
  KBIRequestHandler handler;
  final static int SSH_MSG_USERAUTH_INFO_REQUEST = 60;
  final static int SSH_MSG_USERAUTH_INFO_RESPONSE = 61;

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getMethod() {
      return "keyboard-interactive";
  }

  /**
   * Set the <a href="KBIRequestHandler.html">KBIRequestHandler</a> for this authentication
   * attempt.
   *
   * @param handler
   */
  public void setKBIRequestHandler(KBIRequestHandler handler) {
    this.handler = handler;
  }

  public void authenticate(
      AuthenticationProtocol authentication,
      String servicename) throws SshException, AuthenticationResult {

    try {
      if(handler == null) {
        throw new SshException(
           "A request handler must be set!",
           SshException.BAD_API_USAGE);
      }

      // Send the authentication request
      ByteArrayWriter baw = new ByteArrayWriter();
      baw.writeString("");
      baw.writeString("");

      authentication.sendRequest(username, servicename, "keyboard-interactive",
                                 baw.toByteArray());

      // Read a message
      while(true) {
        byte[] msg = authentication.readMessage();
        ByteArrayReader bar = new ByteArrayReader(msg);

        if(bar.read() != SSH_MSG_USERAUTH_INFO_REQUEST) {
          authentication.transport.disconnect(TransportProtocol.PROTOCOL_ERROR,
             "Unexpected authentication message received!");
          throw new SshException("Unexpected authentication message received!",
                                 SshException.PROTOCOL_VIOLATION);
        }

        String name = bar.readString();
        String instruction = bar.readString();
        @SuppressWarnings("unused")
		String langtag = bar.readString();

        int num = (int)bar.readInt();
        String prompt;
        boolean echo;
        KBIPrompt[] prompts = new KBIPrompt[num];
        for(int i = 0; i < num; i++) {
          prompt = bar.readString();
          echo = (bar.read() == 1);
          prompts[i] = new KBIPrompt(prompt, echo);
        }

        if(!handler.showPrompts(name,
                            instruction, prompts)) {
        	throw new AuthenticationResult(SshAuthentication.CANCELLED);
        }

        baw.reset();
        baw.write(SSH_MSG_USERAUTH_INFO_RESPONSE);
        baw.writeInt(prompts.length);

        for(int i = 0; i < prompts.length; i++) {
          baw.writeString(prompts[i].getResponse());
        }

        authentication.transport.sendMessage(baw.toByteArray(), true);
      }
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }

  }

  /**
   *
   * @return "keyboard-interactive"
   */
  public String getMethodName() {
    return "keyboard-interactive";
  }

}

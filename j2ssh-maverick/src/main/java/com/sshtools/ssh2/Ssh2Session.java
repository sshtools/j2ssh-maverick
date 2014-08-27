
package com.sshtools.ssh2;

import java.io.IOException;
import java.io.InputStream;

import com.sshtools.events.Event;
import com.sshtools.events.EventLog;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.events.J2SSHEventCodes;
import com.sshtools.ssh.ChannelAdapter;
import com.sshtools.ssh.PseudoTerminalModes;
import com.sshtools.ssh.SshChannel;
import com.sshtools.ssh.SshClient;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshSession;
import com.sshtools.ssh.message.SshChannelMessage;
import com.sshtools.ssh.message.SshMessage;
import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;

/**
     * This class implements the SSH2 session channel, unlike SSH1 multiple sessions
 * can be opened on the same SSH connection.
 *
 * @author Lee David Painter
 */
public class Ssh2Session
    extends Ssh2Channel
    implements SshSession {

  final static int SSH_EXTENDED_DATA_STDERR = 1;
  ChannelInputStream stderr;
  boolean flowControlEnabled = false;
  int exitcode = EXITCODE_NOT_RECEIVED;
  String exitsignalinfo = "";
  Ssh2Client client;

  /**
   * Construct a session channel.
   * @param windowsize the initial/maximum window space available
   * @param packetsize the maximum packet size
   */
  public Ssh2Session(int windowsize, int packetsize, Ssh2Client client) {
    super(SESSION_CHANNEL, windowsize, packetsize);
    this.client = client;
    stderr = createExtendedDataStream();
  }

  public SshClient getClient() {
    return client;
  }

  protected void processExtendedData(int typecode,
			 int length,
          SshChannelMessage msg) throws SshException {

	    super.processExtendedData(typecode, length,
                msg);

		if (typecode == SSH_EXTENDED_DATA_STDERR) {
		stderr.addMessage(length, msg);
		}
  }

  public InputStream getStderrInputStream() {
    return stderr;
  }

  public boolean requestPseudoTerminal(String term,
                                       int cols,
                                       int rows,
                                       int width,
                                       int height) throws SshException {
    return requestPseudoTerminal(term, cols, rows, width, height, new byte[] {0});
  }

  public boolean requestPseudoTerminal(String term,
							            int cols,
							            int rows,
							            int width,
							            int height,
							            PseudoTerminalModes terminalModes)
          	throws SshException {
	  
      return requestPseudoTerminal(term,
						            cols,
						            rows,
						            width,
						            height,
						            terminalModes.toByteArray());
  }

  public boolean requestPseudoTerminal(String term,
                                       int cols,
                                       int rows,
                                       int width,
                                       int height,
                                       byte[] modes) throws SshException {

    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeString(term);
      request.writeInt(cols);
      request.writeInt(rows);
      request.writeInt(width);
      request.writeInt(height);
      request.writeBinaryString(modes);
      return sendRequest("pty-req", true, request.toByteArray());
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }

  public boolean startShell() throws SshException {

      // #ifdef DEBUG
      addChannelEventListener(new CommandLogger());
      // #endif
      
	  boolean success = sendRequest("shell", true, null);
      if(success) {
    	  EventServiceImplementation.getInstance().fireEvent(new Event(this,J2SSHEventCodes.EVENT_SHELL_SESSION_STARTED,true));
      } else {
          EventServiceImplementation.getInstance().fireEvent(new Event(this,J2SSHEventCodes.EVENT_SHELL_SESSION_FAILED_TO_START,false));
      }
      
      return success;
	  
	  
  }

  public boolean executeCommand(String cmd) throws SshException {
	  
      // #ifdef DEBUG
      addChannelEventListener(new CommandLogger());
      // #endif
      
    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeString(cmd);
      boolean success=sendRequest("exec", true, request.toByteArray());
      if(success) {
    	  EventServiceImplementation.getInstance().fireEvent((new Event(this,J2SSHEventCodes.EVENT_SHELL_COMMAND,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
      } else {
    	  EventServiceImplementation.getInstance().fireEvent((new Event(this,J2SSHEventCodes.EVENT_SHELL_COMMAND,false)).addAttribute(J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
      }
      
      return success;
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }

  public boolean executeCommand(String cmd, String charset) throws SshException {
    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeString(cmd, charset);
      boolean success = sendRequest("exec", true, request.toByteArray());
      if(success) {
    	  EventServiceImplementation.getInstance().fireEvent((new Event(this,J2SSHEventCodes.EVENT_SHELL_COMMAND,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
      } else {
    	  EventServiceImplementation.getInstance().fireEvent((new Event(this,J2SSHEventCodes.EVENT_SHELL_COMMAND,false)).addAttribute(J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
      }
      
      return success;
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }
  /**
   * SSH2 supports special subsystems that are identified by a name rather than a command
   * string, an example of an SSH2 subsystem is SFTP.
   * @param subsystem the name of the subsystem, for example "sftp"
   * @return <code>true</code> if the subsystem was started, otherwise <code>false</code>
   * @throws SshException
   */
  public boolean startSubsystem(String subsystem) throws SshException {
    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeString(subsystem);
      boolean success = sendRequest("subsystem", true, request.toByteArray());
      if(success) {
    	  EventServiceImplementation.getInstance().fireEvent((new Event(this,J2SSHEventCodes.EVENT_SUBSYSTEM_STARTED,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_COMMAND, subsystem));
      } else {
    	  EventServiceImplementation.getInstance().fireEvent((new Event(this,J2SSHEventCodes.EVENT_SUBSYSTEM_STARTED,false)).addAttribute(J2SSHEventCodes.ATTRIBUTE_COMMAND, subsystem));
      }
      
      return success;
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }

  }

  /**
   * Send a request for X Forwarding.
   * @param singleconnection
   * @param protocol
   * @param cookie
   * @param display
   * @return boolean
   * @throws SshException
   */
  boolean requestX11Forwarding(boolean singleconnection,
           String protocol,
           String cookie,
           int screen) throws SshException {
  try {
    ByteArrayWriter request = new ByteArrayWriter();
    request.writeBoolean(singleconnection);
    request.writeString(protocol);
    request.writeString(cookie);
    request.writeInt(screen); 
    return sendRequest("x11-req", true, request.toByteArray());
  }
  catch(IOException ex) {
    throw new SshException(ex,
                           SshException.INTERNAL_ERROR);
  }
   }

  /**
   * The SSH2 session supports the setting of environments variables however in our experiance
   * no server to date allows unconditional setting of variables. This method should be called
   * before the command is started.
   */
  public boolean setEnvironmentVariable(String name, String value) throws
      SshException {
    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeString(name);
      request.writeString(value);

      return sendRequest("env", true, request.toByteArray());
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }

  public void changeTerminalDimensions(int cols, int rows, int width,
                                       int height) throws SshException {
    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeInt(cols);
      request.writeInt(rows);
      request.writeInt(height);
      request.writeInt(width);

      sendRequest("window-change", false, request.toByteArray());
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }

  }

  /**
   * On many systems it is possible to determine whether a pseudo-terminal is using control-S/
   * control-Q flow control. When flow control is allowed it is often esirable to do the flow control at the
   * client end to speed up responses to user requests. If this method returns <code>true</code> the
   * client is allowed to do flow control using control-S and control-Q
   * @return boolean
   */
  public boolean isFlowControlEnabled() {
    return flowControlEnabled;
  }

  /**
   * Send a signal to the remote process. A signal can be delivered to the remote process using
   * this method, some systems may not implement signals. The signal name should be one
   * of the following values:
   * <blockquote><pre>
   * ABRT
   * ALRM
   * FPE
   * HUP
   * ILL
   * INT
   * KILL
   * PIPE
   * QUIT
   * SEGV
   * TERM
   * USR1
   * USR2
   * </pre></blockquote>
   * @param signal
   * @throws IOException
   */
  public void signal(String signal) throws SshException {
    try {
      ByteArrayWriter request = new ByteArrayWriter();
      request.writeString(signal);

      sendRequest("signal", false, request.toByteArray());
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }

  /**
       * This overidden method handles the "exit-status", "exit-signal" and "xon-xoff"
   * channel requests.
   */
  protected void channelRequest(String requesttype, boolean wantreply,
                                byte[] requestdata) throws SshException {

    try {
      if(requesttype.equals("exit-status")) {
        if(requestdata != null) {
          exitcode = (int)ByteArrayReader.readInt(requestdata, 0);
        }
      }

      if(requesttype.equals("exit-signal")) {

        if(requestdata != null) {
          ByteArrayReader bar = new ByteArrayReader(requestdata, 0,
             requestdata.length);
          exitsignalinfo = "Signal=" + bar.readString()
             + " CoreDump=" + String.valueOf(bar.read() != 0)
             + " Message=" + bar.readString();
        }

      }

      if(requesttype.equals("xon-xoff")) {
        flowControlEnabled = (requestdata != null && requestdata[0] != 0);
      }

      super.channelRequest(requesttype, wantreply, requestdata);
    }
    catch(IOException ex) {
      throw new SshException(ex,
                             SshException.INTERNAL_ERROR);
    }
  }

  public int exitCode() {
    return exitcode;
  }
  
  protected void checkCloseStatus(boolean remoteClosed) {
	  if(!remoteClosed) {
          try {
        	// #ifdef DEBUG
              EventLog.LogEvent(this,"Waiting for remote channel close id=" + channelid + " rid=" + remoteid);
            // #endif
             SshMessage message = ms.nextMessage(CHANNEL_CLOSE_MESSAGES, 
  					Integer.parseInt(System.getProperty("maverick.remoteCloseTimeoutMs", "5000")));
			 if(message!=null) {
				 remoteClosed = true;
					// #ifdef DEBUG
		            EventLog.LogEvent(this,"Remote channel is closed id=" + channelid + " rid=" + remoteid);
		            // #endif
			 } else {
					// #ifdef DEBUG
		            EventLog.LogEvent(this,"Remote channel IS NOT closed id=" + channelid + " rid=" + remoteid);
		            // #endif				 
			 }

		} catch (Exception e) {
		}
      } 
	  
	  super.checkCloseStatus(remoteClosed);
  }

  /**
   * Determine whether the remote process was signalled.
   * @return <code>true</code> if a signal was received, otherwise <code>false</code>
   */
  public boolean hasExitSignal() {
    return!exitsignalinfo.equals("");
  }

  /**
   * Get the exit signal information, may be an empty string.
   * @return String
   */
  public String getExitSignalInfo() {
    return exitsignalinfo;
  }
  
  class CommandLogger extends ChannelAdapter {

	public void dataReceived(SshChannel channel, byte[] buf, int off, int len) {
		EventLog.LogEvent(this,	"Session IN: " + new String(buf, off, len));
	}

	public void dataSent(SshChannel channel, byte[] buf, int off, int len) {
		EventLog.LogEvent(this,	"Session OUT: " + new String(buf, off, len));
	}
	  
  }

}

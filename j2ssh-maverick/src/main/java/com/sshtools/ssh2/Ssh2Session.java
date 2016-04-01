/**
 * Copyright 2003-2016 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
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
import java.io.InputStream;

import com.sshtools.events.Event;
import com.sshtools.events.EventServiceImplementation;
import com.sshtools.events.J2SSHEventCodes;
import com.sshtools.logging.Log;
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
public class Ssh2Session extends Ssh2Channel implements SshSession {

	final static int SSH_EXTENDED_DATA_STDERR = 1;
	ChannelInputStream stderr;
	boolean flowControlEnabled = false;
	int exitcode = EXITCODE_NOT_RECEIVED;
	String exitsignalinfo = "";
	Ssh2Client client;

	/**
	 * Construct a session channel.
	 * 
	 * @param windowsize
	 *            the initial/maximum window space available
	 * @param packetsize
	 *            the maximum packet size
	 */
	public Ssh2Session(int windowsize, int packetsize, Ssh2Client client) {
		super(SESSION_CHANNEL, windowsize, packetsize);
		this.client = client;
		stderr = createExtendedDataStream();
	}

	public SshClient getClient() {
		return client;
	}

	protected void processExtendedData(int typecode, int length,
			SshChannelMessage msg) throws SshException {

		super.processExtendedData(typecode, length, msg);

		if (typecode == SSH_EXTENDED_DATA_STDERR) {
			stderr.addMessage(length, msg);
		}
	}

	public InputStream getStderrInputStream() {
		return stderr;
	}

	public boolean requestPseudoTerminal(String term, int cols, int rows,
			int width, int height) throws SshException {
		return requestPseudoTerminal(term, cols, rows, width, height,
				new byte[] { 0 });
	}

	public boolean requestPseudoTerminal(String term, int cols, int rows,
			int width, int height, PseudoTerminalModes terminalModes)
			throws SshException {

		return requestPseudoTerminal(term, cols, rows, width, height,
				terminalModes.toByteArray());
	}

	public boolean requestPseudoTerminal(String term, int cols, int rows,
			int width, int height, byte[] modes) throws SshException {
		ByteArrayWriter request = new ByteArrayWriter();

		try {

			request.writeString(term);
			request.writeInt(cols);
			request.writeInt(rows);
			request.writeInt(width);
			request.writeInt(height);
			request.writeBinaryString(modes);
			return sendRequest("pty-req", true, request.toByteArray());
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}
	}

	public boolean startShell() throws SshException {

		if (Log.isDebugEnabled()) {
			addChannelEventListener(new CommandLogger());
		}

		boolean success = sendRequest("shell", true, null);
		if (success) {
			EventServiceImplementation.getInstance().fireEvent(
					new Event(this,
							J2SSHEventCodes.EVENT_SHELL_SESSION_STARTED, true));
		} else {
			EventServiceImplementation
					.getInstance()
					.fireEvent(
							new Event(
									this,
									J2SSHEventCodes.EVENT_SHELL_SESSION_FAILED_TO_START,
									false));
		}

		return success;

	}

	public boolean executeCommand(String cmd) throws SshException {

		if (Log.isDebugEnabled()) {
			addChannelEventListener(new CommandLogger());
		}

		ByteArrayWriter request = new ByteArrayWriter();

		try {

			request.writeString(cmd);
			boolean success = sendRequest("exec", true, request.toByteArray());
			if (success) {
				EventServiceImplementation.getInstance().fireEvent(
						(new Event(this, J2SSHEventCodes.EVENT_SHELL_COMMAND,
								true)).addAttribute(
								J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
			} else {
				EventServiceImplementation.getInstance().fireEvent(
						(new Event(this, J2SSHEventCodes.EVENT_SHELL_COMMAND,
								false)).addAttribute(
								J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
			}

			return success;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}
	}

	public boolean executeCommand(String cmd, String charset)
			throws SshException {

		ByteArrayWriter request = new ByteArrayWriter();

		try {

			request.writeString(cmd, charset);
			boolean success = sendRequest("exec", true, request.toByteArray());
			if (success) {
				EventServiceImplementation.getInstance().fireEvent(
						(new Event(this, J2SSHEventCodes.EVENT_SHELL_COMMAND,
								true)).addAttribute(
								J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
			} else {
				EventServiceImplementation.getInstance().fireEvent(
						(new Event(this, J2SSHEventCodes.EVENT_SHELL_COMMAND,
								false)).addAttribute(
								J2SSHEventCodes.ATTRIBUTE_COMMAND, cmd));
			}

			return success;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * SSH2 supports special subsystems that are identified by a name rather
	 * than a command string, an example of an SSH2 subsystem is SFTP.
	 * 
	 * @param subsystem
	 *            the name of the subsystem, for example "sftp"
	 * @return <code>true</code> if the subsystem was started, otherwise
	 *         <code>false</code>
	 * @throws SshException
	 */
	public boolean startSubsystem(String subsystem) throws SshException {

		ByteArrayWriter request = new ByteArrayWriter();
		try {

			request.writeString(subsystem);
			boolean success = sendRequest("subsystem", true,
					request.toByteArray());
			if (success) {
				EventServiceImplementation.getInstance().fireEvent(
						(new Event(this,
								J2SSHEventCodes.EVENT_SUBSYSTEM_STARTED, true))
								.addAttribute(
										J2SSHEventCodes.ATTRIBUTE_COMMAND,
										subsystem));
			} else {
				EventServiceImplementation
						.getInstance()
						.fireEvent(
								(new Event(
										this,
										J2SSHEventCodes.EVENT_SUBSYSTEM_STARTED,
										false)).addAttribute(
										J2SSHEventCodes.ATTRIBUTE_COMMAND,
										subsystem));
			}

			return success;
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}

	}

	/**
	 * Send a request for X Forwarding.
	 * 
	 * @param singleconnection
	 * @param protocol
	 * @param cookie
	 * @param display
	 * @return boolean
	 * @throws SshException
	 */
	boolean requestX11Forwarding(boolean singleconnection, String protocol,
			String cookie, int screen) throws SshException {
		ByteArrayWriter request = new ByteArrayWriter();
		try {

			request.writeBoolean(singleconnection);
			request.writeString(protocol);
			request.writeString(cookie);
			request.writeInt(screen);
			return sendRequest("x11-req", true, request.toByteArray());
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * The SSH2 session supports the setting of environments variables however
	 * in our experiance no server to date allows unconditional setting of
	 * variables. This method should be called before the command is started.
	 */
	public boolean setEnvironmentVariable(String name, String value)
			throws SshException {
		ByteArrayWriter request = new ByteArrayWriter();
		try {
			request.writeString(name);
			request.writeString(value);

			return sendRequest("env", true, request.toByteArray());
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}
	}

	public void changeTerminalDimensions(int cols, int rows, int width,
			int height) throws SshException {

		ByteArrayWriter request = new ByteArrayWriter();
		try {

			request.writeInt(cols);
			request.writeInt(rows);
			request.writeInt(height);
			request.writeInt(width);

			sendRequest("window-change", false, request.toByteArray());
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}

	}

	/**
	 * On many systems it is possible to determine whether a pseudo-terminal is
	 * using control-S/ control-Q flow control. When flow control is allowed it
	 * is often esirable to do the flow control at the client end to speed up
	 * responses to user requests. If this method returns <code>true</code> the
	 * client is allowed to do flow control using control-S and control-Q
	 * 
	 * @return boolean
	 */
	public boolean isFlowControlEnabled() {
		return flowControlEnabled;
	}

	/**
	 * Send a signal to the remote process. A signal can be delivered to the
	 * remote process using this method, some systems may not implement signals.
	 * The signal name should be one of the following values: <blockquote>
	 * 
	 * <pre>
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
	 * </pre>
	 * 
	 * </blockquote>
	 * 
	 * @param signal
	 * @throws IOException
	 */
	public void signal(String signal) throws SshException {

		ByteArrayWriter request = new ByteArrayWriter();
		try {

			request.writeString(signal);

			sendRequest("signal", false, request.toByteArray());
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		} finally {
			try {
				request.close();
			} catch (IOException e) {
			}
		}
	}

	/**
	 * This overidden method handles the "exit-status", "exit-signal" and
	 * "xon-xoff" channel requests.
	 */
	protected void channelRequest(String requesttype, boolean wantreply,
			byte[] requestdata) throws SshException {

		try {
			if (requesttype.equals("exit-status")) {
				if (requestdata != null) {
					exitcode = (int) ByteArrayReader.readInt(requestdata, 0);
				}
			}

			if (requesttype.equals("exit-signal")) {

				if (requestdata != null) {
					ByteArrayReader bar = new ByteArrayReader(requestdata, 0,
							requestdata.length);
					try {
						exitsignalinfo = "Signal=" + bar.readString()
								+ " CoreDump="
								+ String.valueOf(bar.read() != 0) + " Message="
								+ bar.readString();
					} finally {
						try {
							bar.close();
						} catch (IOException e) {
						}
					}
				}

			}

			if (requesttype.equals("xon-xoff")) {
				flowControlEnabled = (requestdata != null && requestdata[0] != 0);
			}

			super.channelRequest(requesttype, wantreply, requestdata);
		} catch (IOException ex) {
			throw new SshException(ex, SshException.INTERNAL_ERROR);
		}
	}

	public int exitCode() {
		return exitcode;
	}

	protected void checkCloseStatus(boolean remoteClosed) {
		if (!remoteClosed) {
			try {
				if (Log.isDebugEnabled()) {
					Log.debug(this,
							"Waiting for remote channel close id=" + channelid
									+ " rid=" + remoteid);
				}
				SshMessage message = ms.nextMessage(CHANNEL_CLOSE_MESSAGES,
						Integer.parseInt(System.getProperty(
								"maverick.remoteCloseTimeoutMs", "5000")));
				if (message != null) {
					remoteClosed = true;
					if (Log.isDebugEnabled()) {
						Log.debug(this, "Remote channel is closed id="
								+ channelid + " rid=" + remoteid);
					}
				} else {
					if (Log.isDebugEnabled()) {
						Log.debug(this,
								"Remote channel IS NOT closed id=" + channelid
										+ " rid=" + remoteid);
					}
				}

			} catch (Exception e) {
			}
		}

		super.checkCloseStatus(remoteClosed);
	}

	/**
	 * Determine whether the remote process was signalled.
	 * 
	 * @return <code>true</code> if a signal was received, otherwise
	 *         <code>false</code>
	 */
	public boolean hasExitSignal() {
		return !exitsignalinfo.equals("");
	}

	/**
	 * Get the exit signal information, may be an empty string.
	 * 
	 * @return String
	 */
	public String getExitSignalInfo() {
		return exitsignalinfo;
	}

	class CommandLogger extends ChannelAdapter {

		public void dataReceived(SshChannel channel, byte[] buf, int off,
				int len) {
			Log.info(this, "Session IN: " + new String(buf, off, len));
		}

		public void dataSent(SshChannel channel, byte[] buf, int off, int len) {
			Log.info(this, "Session OUT: " + new String(buf, off, len));
		}

	}

}

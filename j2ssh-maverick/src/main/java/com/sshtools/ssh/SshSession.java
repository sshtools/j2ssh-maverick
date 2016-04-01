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
package com.sshtools.ssh;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * <p>
 * Base interface for SSH sessions supporting all the features common to both
 * SSH1 and SSH2. Sessions are created through the <a
 * href="SshClient.html#openSessionChannel()">openSessionChannel()</a> method of
 * the <a href="SshClient.html">SshClient</a>. Once a session has been obtained
 * the session will not be active until you either call <a
 * href="#executeCommand(java.lang.String)">executeCommand(String command)<a> or
 * <a href="#startShell()">startShell()<a>. Once activated you can use the IO
 * streams to read and write to the remote process. The following code shows the
 * basic process: <blockquote>
 * 
 * <pre>
 * SshConnector con = SshConnector.getInstance();
 * SshClient ssh = con.connect(
 * 	new SocketTransport("beagle2.sshtools.net", 22),
 * 	"martianx");
 * 
 * PasswordAuthentication pwd = new PasswordAuthentication();
 * pwd.setPassword("likeidgivethataway!");
 * 
 * if(ssh.authenticate(pwd)==SshAuthentication.COMPLETE) {
 * 	SshSession sesison = ssh.openSessionChannel();
 * 
 *      if(session.requestPseudoTerminal("vt100",
 * 			80,
 * 			24,
 * 			 0,
 * 			 0)) {
 *           session.startShell();
 * 
 *           session.getOutputStream().write("ls\n".getBytes());
 *      }
 * } else {
 * 	System.out.println("Authentication failed");
 * }
 * 
 * 
 * SshSession objects can't maintain state so performing a "cd c:\\temp" command would have no effect instead the Shell class should be used.
 * 
 * </pre>
 * 
 * </blockquote>
 * 
 * @author Lee David Painter
 * @see com.sshtools.ssh1.Ssh1Session
 * @see com.sshtools.ssh2.Ssh2Session
 */
public interface SshSession extends SshChannel {

	/**
	 * Returned from exitCode() when the remote process is still active. NOTE:
	 * This may still be returned once the channel has been closed and should
	 * not be used as an indication of the remote process state.
	 **/
	public static final int EXITCODE_NOT_RECEIVED = Integer.MIN_VALUE;

	/**
	 * Start the users default shell.
	 * 
	 * @return <code>true</code> if the shell was started, otherwise
	 *         <code>false</code>
	 * @throws SshException
	 */
	public boolean startShell() throws SshException;

	/**
	 * Get the client that created this session.
	 * 
	 * @return SshClient
	 */
	public SshClient getClient();

	/**
	 * Execute a command.
	 * 
	 * An important note to remember is that this does not execute a shell
	 * command. You cannot for instance issue the command executeCommand("dir")"
	 * on the Windows Operating system as this is a shell command, instead use
	 * "cmd.exe /C dir". This method executes a binary executable and so should
	 * be used to execute any program other than the users shell.
	 * 
	 * Calls to this method should only be used to execute commands that are
	 * indedependent, such as "mkdir /home/david/newfolder".
	 * 
	 * @param cmd
	 * @return <code>true</code> if the command was accepted, otherwise
	 *         <code>false</code>. This may not return false if the command is
	 *         incorrect, it should only be used as an indication that the
	 *         command was accepted and that the server will attempt to execute
	 *         it.
	 * @throws SshException
	 */
	public boolean executeCommand(String cmd) throws SshException;

	/**
	 * Execute a command.
	 * 
	 * An important note to remember is that this does not execute a shell
	 * command. You cannot for instance issue the command executeCommand("dir")"
	 * on the Windows Operating system as this is a shell command, instead use
	 * "cmd.exe /C dir". This method executes a binary executable and so should
	 * be used to execute any program other than the users shell.
	 * 
	 * Calls to this method should only be used to execute commands that are
	 * indedependent, such as "mkdir /home/david/newfolder".
	 * 
	 * @param cmd
	 * @return <code>true</code> if the command was accepted, otherwise
	 *         <code>false</code>. This may not return false if the command is
	 *         incorrect, it should only be used as an indication that the
	 *         command was accepted and that the server will attempt to execute
	 *         it.
	 * @throws SshException
	 */
	public boolean executeCommand(String cmd, String charset)
			throws SshException;

	/**
	 * The remote process may require a pseudo terminal. Call this method before
	 * executing a command or starting a shell.
	 * 
	 * @param term
	 *            the terminal type e.g "vt100"
	 * @param cols
	 *            the number of columns
	 * @param rows
	 *            the number of rows
	 * @param width
	 *            the width of the terminal (informational only, can be zero)
	 * @param height
	 *            the height of the terminal (informational only, can be zero)
	 * @param modes
	 *            an array of encoded terminal modes as described in the SSH
	 *            protocol specifications.
	 * 
	 * @return <code>true</code> if the pty was allocated, otherwise
	 *         <code>false</code>
	 * @throws SshException
	 */
	public boolean requestPseudoTerminal(String term, int cols, int rows,
			int width, int height, byte[] modes) throws SshException;

	/**
	 * The remote process may require a pseudo terminal. Call this method before
	 * executing a command or starting a shell.
	 * 
	 * @param term
	 *            the terminal type e.g "vt100"
	 * @param cols
	 *            the number of columns
	 * @param rows
	 *            the number of rows
	 * @param width
	 *            the width of the terminal (informational only, can be zero)
	 * @param height
	 *            the height of the terminal (informational only, can be zero)
	 * @param terminalModes
	 *            the known terminal modes
	 * 
	 * @return <code>true</code> if the pty was allocated, otherwise
	 *         <code>false</code>
	 * @throws SshException
	 */
	public boolean requestPseudoTerminal(String term, int cols, int rows,
			int width, int height, PseudoTerminalModes terminalModes)
			throws SshException;

	/**
	 * The remote process may require a pseudo terminal. Call this method before
	 * executing a command or starting a shell.
	 * 
	 * @param term
	 *            the terminal type e.g "vt100"
	 * @param cols
	 *            the number of columns
	 * @param rows
	 *            the number of rows
	 * @param width
	 *            the width of the terminal (informational only, can be zero)
	 * @param height
	 *            the height of the terminal (informational only, can be zero)
	 * @return <code>true</code> if the pty was allocated, otherwise
	 *         <code>false</code>
	 * @throws SshException
	 */
	public boolean requestPseudoTerminal(String term, int cols, int rows,
			int width, int height) throws SshException;

	/**
	 * Get an InputStream to read the process stdout.
	 * 
	 * @return the sessions InputStream
	 * @throws SshException
	 */
	public InputStream getInputStream() throws SshIOException;

	/**
	 * Get an OutputStream to write to the process stdin.
	 * 
	 * @return the sessions OutputStream
	 * @throws SshException
	 */
	public OutputStream getOutputStream() throws SshIOException;

	/**
	 * Get an InputStream to read the process stderr.
	 * 
	 * @return the sessions stderr InputStream
	 * @throws SshException
	 */
	public InputStream getStderrInputStream() throws SshIOException;

	/**
	 * Close the session.
	 */
	public void close();

	/**
	 * Return the exit code of the process once complete. Call this after the
	 * session has been closed to obtain the exit code of the process. It MAY or
	 * MAY NOT be sent by the server. If the exit code was not received this
	 * method will return EXITCODE_NOT_RECEIVED.
	 * 
	 * @return the exit code value or SshSession.EXITCODE_NOT_RECEIVED
	 */
	public int exitCode();

	/**
	 * Change the dimensions of the terminal window. This method should be
	 * called when the session is active and the user or application changes the
	 * size of the terminal window.
	 * 
	 * @param cols
	 * @param rows
	 * @param width
	 * @param height
	 * @throws SshException
	 */
	public void changeTerminalDimensions(int cols, int rows, int width,
			int height) throws SshException;

	/**
	 * Evaluate whether the channel is closed.
	 * 
	 * @return <code>true</code> if the session is closed, otherwise
	 *         <code>false</code>
	 */
	public boolean isClosed();

}

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

package com.sshtools.scp;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import com.sshtools.sftp.FileTransferProgress;
import com.sshtools.sftp.GlobRegExpMatching;
import com.sshtools.sftp.SftpStatusException;
import com.sshtools.ssh.ChannelOpenException;
import com.sshtools.ssh.Client;
import com.sshtools.ssh.SshClient;
import com.sshtools.ssh.SshException;
import com.sshtools.ssh.SshIOException;
import com.sshtools.ssh.SshSession;

/**
 * Implements an SCP (Secure Copy) client which may be useful for SSH1
 * connections and SSH2 where SFTP is not available.
 * 
 * @author Lee David Painter
 */
public class ScpClient extends ScpClientIO implements Client {

    File cwd;

    /**
     * <p>
     * Creates an SCP client. CWD (Current working directory) will be the users
     * home directory.
     * </p>
     * 
     * @param ssh A connected SshClient
     */
    public ScpClient(SshClient ssh) {
        this(null, ssh);
    }

    /**
     * <p>
     * Creates an SCP client.
     * </p>
     * 
     * @param cwd The current local directory
     * @param ssh A connected SshClient
     */
    public ScpClient(File cwd, SshClient ssh) {
        super(ssh);
    	String homeDir="";
    	if(cwd==null) {
	    	try {
	    		homeDir=System.getProperty("user.home");
	    	} catch(SecurityException e) {
	    		//ignore
	    	}
	    	cwd=new File(homeDir);
    	}
        this.cwd = cwd;
    }

   /**
     * <p>
     * Uploads a local file onto the remote server.
     * </p>
     * 
     * <p>Treats localFile as a glob regular expression, and puts the files that match into the remote directory.</p>
     * 
     * <p>Code examples can be found in ScpConnect.java</p>
     * 
     * <p>Code Example<br>
     * <blockquote><pre>
     * //put all .doc files with 'rfc' in their names, in the 'docs/unsorted/' folder relative to the local cwd, and copy them to remoteFile.  If remoteFile is a filename then the remote file will have this name unless multiple local files are matched in which case an exception will be thrown.
     * scp.put("docs/unsorted/*rfc*.doc"); 
     * </pre></blockquote></p>
     * 
     * @param localFile The path to the local file relative to the local current
     *        directory; may be a file or directory
     * @param remoteFile The path on the remote server, may be a file or
     *        directory
     * @param recursive Copy the contents of a directory recursivly
     * 
     * @throws SshException if an IO error occurs during the operation
     * @throws SftpStatusException
     */
    public void put(String localFile, String remoteFile, boolean recursive) throws SshException, ChannelOpenException,
                    SftpStatusException {
        put(localFile, remoteFile, recursive, null);
    }

    /**
     * @param localFile
     * @param remoteFile
     * @param recursive
     * @param progress
     * @param remoteIsDir if called by put(string[]...) then remoteFile must be
     *        a directory so need -d option.
     * @throws SshException
     * @throws ChannelOpenException
     */
    public void putFile(String localFile, String remoteFile, boolean recursive, FileTransferProgress progress, boolean remoteIsDir)
                    throws SshException, ChannelOpenException {

        File lf = new File(localFile);
        
        //remoteFile = remoteFile.replace('\\', '/');
        
        if (!lf.isAbsolute()) {
            lf = new File(cwd, localFile);
        }

        if (!lf.exists()) {
            throw new SshException(localFile + " does not exist", SshException.CHANNEL_FAILURE);
        }

        if (!lf.isFile() && !lf.isDirectory()) {
            throw new SshException(localFile + " is not a regular file or directory", SshException.CHANNEL_FAILURE);
        }

        if (lf.isDirectory() && !recursive) {
            throw new SshException(localFile + " is a directory, use recursive mode", SshException.CHANNEL_FAILURE);
        }

        if ((remoteFile == null) || remoteFile.equals("")) {
            remoteFile = ".";
        }

        ScpEngine scp = new ScpEngine("scp " + ((lf.isDirectory() | remoteIsDir) ? "-d " : "") + "-t " + (recursive ? "-r " : "")
                        + remoteFile, ssh.openSessionChannel());
        try {

            scp.waitForResponse();

            scp.writeFileToRemote(lf, recursive, progress);

        } catch (SshIOException ex) {
            throw ex.getRealException();
        } catch (IOException ex) {

            throw new SshException("localfile="+localFile + " remotefile="+remoteFile, SshException.CHANNEL_FAILURE, ex);
        } finally {
        	
        	try {
        		scp.close();
        	} catch(Throwable t) { }
        }

    }

    /**
     * pattern
     * matches the files in the local directory using "local" as a glob Regular
     * Expression. For the matching file array put is called to copy the file to
     * the remote directory.
     * 
     * @param localFileRegExp
     * @param remoteFile
     * @param recursive
     * @param progress
     * @throws SshException
     * @throws ChannelOpenException
     */
    public void put(String localFileRegExp, String remoteFile, boolean recursive, FileTransferProgress progress)
                    throws SshException, ChannelOpenException {
        GlobRegExpMatching globMatcher = new GlobRegExpMatching();
        String parentDir;
        int fileSeparatorIndex;
        parentDir=cwd.getAbsolutePath();
        String relativePath = "";
        if ((fileSeparatorIndex = localFileRegExp.lastIndexOf(System.getProperty("file.separator"))) > -1
        		|| (fileSeparatorIndex = localFileRegExp.lastIndexOf('/')) > -1) {
            relativePath=localFileRegExp.substring(0, fileSeparatorIndex+1);
            File rel = new File(relativePath);
            if(rel.isAbsolute())
            {
            	parentDir=relativePath;
            }
            else
            {
            	parentDir+=System.getProperty("file.separator")+relativePath;
            }
        }
        
        File f = new File(parentDir);
        
        //this is 1.2 so do it the long way
        //f.listFiles();
        String[] fileListingStrings=f.list();
        File[] fileListing=new File[fileListingStrings.length];
        for(int i=0;i<fileListingStrings.length;i++) {
        	fileListing[i]=new File(parentDir+File.separator+fileListingStrings[i]);
        }
        
        String[] matchedFiles= globMatcher.matchFileNamesWithPattern(fileListing, localFileRegExp.substring(fileSeparatorIndex+1));
        if (matchedFiles.length == 0) {
            throw new SshException(localFileRegExp+"No file matches/File does not exist", SshException.CHANNEL_FAILURE);
        }
        
        /*if(!relativePath.equals(""))
        	for(int i=0;i<matchedFiles.length;i++)
        		matchedFiles[i] = relativePath + matchedFiles[i];*/
        
		if (matchedFiles.length > 1) {
		    put(matchedFiles, remoteFile, recursive, progress);
		} else {
		    putFile(matchedFiles[0], remoteFile, recursive, progress, false);
		}
    }

    /**
     * <p>
     * Uploads an array of local files onto the remote server.
     * </p>
     * 
     * @param localFiles an array of local files; may be files or directories
     * @param remoteFile the path on the remote server, may be a file or
     *        directory.
     * @param recursive Copy the contents of directorys recursivly
     * 
     * @throws IOException if an IO error occurs during the operation
     */
    public void put(String[] localFiles, String remoteFile, boolean recursive) throws SshException, ChannelOpenException {
        put(localFiles, remoteFile, recursive, null);
    }

    /**
     * <p>
     * Uploads an array of local files onto the remote server.
     * </p>
     * 
     * @param localFiles an array of local files; may be files or directories
     * @param remoteFile the path on the remote server, may be a file or
     *        directory1
     * @param recursive Copy the contents of directorys recursivly
     * 
     * @throws IOException if an IO error occurs during the operation
     */
    public void put(String[] localFiles, String remoteFile, boolean recursive, FileTransferProgress progress) throws SshException,
                    ChannelOpenException {
        for (int i = 0; i < localFiles.length; i++) {
            putFile(localFiles[i], remoteFile, recursive, progress, true);
        }
    }

    /**
     * <p>
     * Downloads an array of remote files to the local computer.
     * </p>
     * 
     * @param localDir The local path to place the files
     * @param remoteFiles The path of the remote files
     * @param recursive recursively copy the contents of a directory
     * 
     * @throws IOException if an IO error occurs during the operation
     */
    public void get(String localDir, String[] remoteFiles, boolean recursive) throws SshException, ChannelOpenException {
        get(localDir, remoteFiles, recursive, null);
    }

    public void get(String localFile, String[] remoteFiles, boolean recursive, FileTransferProgress progress) throws SshException,
                    ChannelOpenException {
        StringBuffer buf = new StringBuffer();

        for (int i = 0; i < remoteFiles.length; i++) {
            buf.append("\"");
            buf.append(remoteFiles[i]);
            buf.append("\" ");
        }

        String remoteFile = buf.toString();
        remoteFile = remoteFile.trim();
        get(localFile, remoteFile, recursive, progress);
    }

    /**
     * <p>
     * Downloads a remote file onto the local computer.
     * </p>
     * 
     * @param localFile The path to place the file
     * @param remoteFile The path of the file on the remote server
     * @param recursive recursivly copy the contents of a directory
     * 
     * @throws IOException if an IO error occurs during the operation
     */
    public void get(String localFile, String remoteFile, boolean recursive) throws SshException, ChannelOpenException {
        get(localFile, remoteFile, recursive, null);
    }

    public void get(String localFile, String remoteFile, boolean recursive, FileTransferProgress progress) throws SshException,
                    ChannelOpenException {
        if ((localFile == null) || localFile.equals("")) {
            localFile = ".";
        }

        File lf = new File(localFile);

        if (!lf.isAbsolute()) {
            lf = new File(cwd, localFile);
        }

        if (lf.exists() && !lf.isFile() && !lf.isDirectory()) {
            throw new SshException(localFile + " is not a regular file or directory", SshException.CHANNEL_FAILURE);
        }

        ScpEngine scp = new ScpEngine("scp " + "-f " + (recursive ? "-r " : "") + remoteFile, ssh.openSessionChannel());

        scp.readFromRemote(lf, progress, false);

        try {
        	// Try and close the SCP client but we can ignore errors now
        	scp.close();
        } catch(Throwable t) { }
    }

    /**
     * <p>
     * Implements an SCP Engine by extending J2SSH Mavericjs ScpEngineIO
     * </p>
     */
    protected class ScpEngine extends ScpClientIO.ScpEngineIO {

        /**
         * <p>
         * Contruct the channel with the specified scp command.
         * </p>
         * 
         * @param cmd The scp command
         */
        protected ScpEngine(String cmd, SshSession session) throws SshException {
            super(cmd, session);

        }

        /**
         * <p>
         * Writes a directory to the remote server.
         * </p>
         * 
         * @param dir The source directory
         * @param recursive Add the contents of the directory recursivley
         * 
         * @return true if the file was written, otherwise false
         * 
         * @throws IOException if an IO error occurs
         */
        private boolean writeDirToRemote(File dir, boolean recursive, FileTransferProgress progress) throws SshException {
            try {
                if (!recursive) {
                    writeError("File " + dir.getName() + " is a directory, use recursive mode");

                    return false;
                }

                String cmd = "D0755 0 " + dir.getName() + "\n";
                out.write(cmd.getBytes());

                waitForResponse();

                String[] list = dir.list();

                for (int i = 0; i < list.length; i++) {
                    File f = new File(dir, list[i]);
                    writeFileToRemote(f, recursive, progress);
                }

                out.write("E\n".getBytes());

                return true;
            } catch (IOException ex) {
                close();
                throw new SshException(ex, SshException.CHANNEL_FAILURE);
            }
        }

        /**
         * <p>
         * Write a file to the remote server.
         * </p>
         * 
         * @param file The source file
         * @param recursive Add the contents of the directory recursivley
         * 
         * @throws IOException if an IO error occurs
         */
        private void writeFileToRemote(File file, boolean recursive, FileTransferProgress progress) throws SshException {
            try {
                if (file.isDirectory()) {
                    if (!writeDirToRemote(file, recursive, progress)) {
                        return;
                    }
                } else if (file.isFile()) {

                    String cmd = "C0644 " + file.length() + " " + file.getName() + "\n";

                    out.write(cmd.getBytes());

                    if (progress != null)
                        progress.started(file.length(), file.getName());

                    waitForResponse();

                    FileInputStream fi = new FileInputStream(file);
                    writeCompleteFile(fi, file.length(), progress);

                    if (progress != null)
                        progress.completed();
                    
                    writeOk();


                } else {
                    throw new SshException(file.getName() + " not valid for SCP", SshException.CHANNEL_FAILURE);
                }

               	waitForResponse();
                
            } catch (SshIOException ex) {
                throw ex.getRealException();
            } catch (IOException ex) {
                close();
                throw new SshException(ex, SshException.CHANNEL_FAILURE);
            }
        }

        private void readFromRemote(File file, FileTransferProgress progress, boolean isDir) throws SshException {
            try {
                String cmd;
                String[] cmdParts = new String[3];

                writeOk();

                while (true) {
                    try {
                        cmd = readString();
                    } catch (EOFException e) {
                        return;
                    } catch(SshIOException e2) {
                    	return;
                    }

                    char cmdChar = cmd.charAt(0);

                    switch (cmdChar) {
                        case 'E':
                            writeOk();

                            return;

                        case 'T':
                            continue;

                        case 'C':
                        case 'D':

                            String targetName = file.getAbsolutePath();
                            parseCommand(cmd, cmdParts);

                            if (file.isDirectory()) {
                                targetName += (File.separator + cmdParts[2]);
                            }

                            File targetFile = new File(targetName);

                            if (cmdChar == 'D') {
                                if (targetFile.exists()) {
                                    if (!targetFile.isDirectory()) {
                                        String msg = "Invalid target " + targetFile.getName() + ", must be a directory";
                                        writeError(msg);
                                        throw new IOException(msg);
                                    }
                                } else {
                                    if (!targetFile.mkdir()) {
                                        String msg = "Could not create directory: " + targetFile.getName();
                                        writeError(msg);
                                        throw new IOException(msg);
                                    }
                                }

                                readFromRemote(targetFile, progress, true);

                                continue;
                            }

                            long len = Long.parseLong(cmdParts[1]);
                            
                            FileOutputStream fo = new FileOutputStream(targetFile);
                            writeOk();

                            if (progress != null)
                                progress.started(len, targetName);

                            readCompleteFile(fo, len, progress);

                            if (progress != null)
                                progress.completed();
                            
                            try {
	                            waitForResponse();
	
	                            writeOk();
                            } catch(SshIOException ex) {
                            	
                            	// Workaround for some old servers that seem to be killing the process early.
                            	if(ex.getRealException().getReason()==SshException.UNEXPECTED_TERMINATION && !isDir) {
                            		return; 
                            	} else {
                            		throw ex;
                            	}
                            }
                            break;

                        default:
                            writeError("Unexpected cmd: " + cmd);
                            throw new IOException("SCP unexpected cmd: " + cmd);
                    }
                }
            } catch (SshIOException ex) {
                throw ex.getRealException();
            } catch (IOException ex) {
                close();
                throw new SshException(ex, SshException.CHANNEL_FAILURE);
            }
        }
    }

	public void exit() throws SshException, IOException {

	}
}

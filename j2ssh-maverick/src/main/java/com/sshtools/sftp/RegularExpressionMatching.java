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
package com.sshtools.sftp;

import java.io.File;

import com.sshtools.ssh.SshException;

/**
 * Interface for treating a filename as a regular expression and returning the
 * list of files that match.
 * 
 * @author David Hodgins
 */
public interface RegularExpressionMatching {

	/**
	 * returns each of the SftpFiles that match the pattern fileNameRegExp
	 * 
	 * @param files
	 * @param fileNameRegExp
	 * @return SftpFile[]
	 * @throws SftpStatusException
	 * @throws SshException
	 */
	public SftpFile[] matchFilesWithPattern(SftpFile[] files,
			String fileNameRegExp) throws SftpStatusException, SshException;

	/**
	 * returns each of the files that match the pattern fileNameRegExp
	 * 
	 * @param files
	 * @param fileNameRegExp
	 * @return String[]
	 * @throws SftpStatusException
	 * @throws SshException
	 */
	public String[] matchFileNamesWithPattern(File[] files,
			String fileNameRegExp) throws SftpStatusException, SshException;

}
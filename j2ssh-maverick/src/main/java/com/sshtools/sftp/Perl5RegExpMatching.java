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
/**
 * 
 */
package com.sshtools.sftp;

import java.io.File;
import java.util.Vector;

import org.apache.oro.text.regex.MalformedPatternException;
import org.apache.oro.text.regex.Pattern;
import org.apache.oro.text.regex.PatternCompiler;
import org.apache.oro.text.regex.PatternMatcher;
import org.apache.oro.text.regex.Perl5Compiler;
import org.apache.oro.text.regex.Perl5Matcher;

import com.sshtools.ssh.SshException;

/**
 * <p>
 * Implements the RegularExpressionMatching Interface.
 * </p>
 * 
 * matchFileNamesWithPattern performs a perl regular expression pattern match on
 * the Files passed to it, using fileNameRegExp, then returns the ones that
 * match.
 * 
 * <p>
 * Code example:
 * </p>
 * <blockquote>
 * 
 * <pre>
 * File f=new File("c:\\homefolder");
 * File[] someFiles;
 * List files in folder f and store in someFiles.
 * someFiles=f.listFiles();
 * Find the '.doc' files in someFiles that have 'rfc' in their name.
 * String[] matchedFiles=matchFileNamesWithPattern(someFiles, "*rfc*.doc");
 * </pre>
 * 
 * </blockquote>
 * <p>
 * matchFilesWithPattern performs a perl regular expression pattern match on the
 * SftpFiles passed to it, using fileNameRegExp, then returns the ones that
 * match.
 * </p>
 */
public class Perl5RegExpMatching implements RegularExpressionMatching {

	/**
	 * compiles fileNameRegExp into a regular expression and pattern matches on
	 * each file's name, and returns those that match.
	 * 
	 * @param files
	 * @param fileNameRegExp
	 * 
	 * @return String[] of file names that match the expresion.
	 */
	public String[] matchFileNamesWithPattern(File[] files,
			String fileNameRegExp) throws SshException {
		// set up variables for regexp matching
		Pattern mpattern = null;
		PatternCompiler aPCompiler = new Perl5Compiler();
		PatternMatcher aPerl5Matcher = new Perl5Matcher();
		// Attempt to compile the pattern. If the pattern is not valid,
		// throw exception
		try {
			mpattern = aPCompiler.compile(fileNameRegExp);
		} catch (MalformedPatternException e) {
			throw new SshException("Invalid regular expression:"
					+ e.getMessage(), SshException.BAD_API_USAGE);
		}

		Vector<String> matchedNames = new Vector<String>();

		for (int i = 0; i < files.length; i++) {
			if ((!files[i].getName().equals("."))
					&& (!files[i].getName().equals(".."))
					&& (!files[i].isDirectory())) {
				if (aPerl5Matcher.matches(files[i].getName(), mpattern)) {
					// call get for each match, passing true, so that it doesnt
					// repeat the search
					matchedNames.addElement(files[i].getName());
				}
			}
		}

		// return (String[]) matchedNames.toArray(new String[0]);
		String[] matchedNamesStrings = new String[matchedNames.size()];
		matchedNames.copyInto(matchedNamesStrings);
		return matchedNamesStrings;
	}

	/**
	 * compiles fileNameRegExp into a regular expression and pattern matches on
	 * each file's name, and returns those that match.
	 * 
	 * @param files
	 * @param fileNameRegExp
	 * 
	 * @return SftpFile[] of files that match the expresion.
	 */
	public SftpFile[] matchFilesWithPattern(SftpFile[] files,
			String fileNameRegExp) throws SftpStatusException, SshException {
		// set up variables for regexp matching
		Pattern mpattern = null;
		PatternCompiler aPCompiler = new Perl5Compiler();
		PatternMatcher aPerl5Matcher = new Perl5Matcher();
		// Attempt to compile the pattern. If the pattern is not valid,
		// throw exception
		try {
			mpattern = aPCompiler.compile(fileNameRegExp);
		} catch (MalformedPatternException e) {
			throw new SshException("Invalid regular expression:"
					+ e.getMessage(), SshException.BAD_API_USAGE);
		}

		Vector<SftpFile> matchedNames = new Vector<SftpFile>();

		for (int i = 0; i < files.length; i++) {
			if ((!files[i].getFilename().equals("."))
					&& (!files[i].getFilename().equals(".."))
					&& (!files[i].isDirectory())) {
				if (aPerl5Matcher.matches(files[i].getFilename(), mpattern)) {
					// call get for each match, passing true, so that it doesnt
					// repeat the search
					matchedNames.addElement(files[i]);
				}
			}
		}

		// return (SftpFile[]) matchedNames.toArray(new SftpFile[0]);
		SftpFile[] matchedNamesSftpFiles = new SftpFile[matchedNames.size()];
		matchedNames.copyInto(matchedNamesSftpFiles);
		return matchedNamesSftpFiles;
	}
}
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

/**
 * Version 4 of the SFTP protocol introduces an ACL field in the
 * {@link SftpFileAttributes} structure.
 * 
 * @author Lee David Painter
 */
public class ACL {

	public static final int ACL_ALLOWED_TYPE = 1;
	public static final int ACL_DENIED_TYPE = 1;
	public static final int ACL_AUDIT_TYPE = 1;
	public static final int ACL_ALARM_TYPE = 1;

	int type;
	int flags;
	int mask;
	String who;

	public ACL(int type, int flags, int mask, String who) {
	}

	public int getType() {
		return type;
	}

	public int getFlags() {
		return flags;
	}

	public int getMask() {
		return mask;
	}

	public String getWho() {
		return who;
	}
}

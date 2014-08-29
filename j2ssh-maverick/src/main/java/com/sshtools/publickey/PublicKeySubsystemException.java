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

package com.sshtools.publickey;

/**
 * Exception thrown by the {@link PublicKeySubsystem} when errors occur in
 * listing, adding or removing keys.
 * 
 * @author Lee David Painter
 */
public class PublicKeySubsystemException extends Exception {

	private static final long serialVersionUID = 1L;
	static final int SUCCESS = 0;
	public static final int ACCESS_DENIED = 1;
	public static final int STORAGE_EXCEEDED = 2;
	public static final int REQUEST_NOT_SUPPPORTED = 3;
	public static final int KEY_NOT_FOUND = 4;
	public static final int KEY_NOT_SUPPORTED = 5;
	public static final int GENERAL_FAILURE = 6;

	int status;

	public PublicKeySubsystemException(int status, String desc) {
		super(desc);
		this.status = status;
	}

	public int getStatus() {
		return status;
	}

}

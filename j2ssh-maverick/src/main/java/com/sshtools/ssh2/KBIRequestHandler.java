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
 * You should have received a copy of the GNU Lesser General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sshtools.ssh2;

/**
 * 
 * Callback interface used by the <a
 * href="KBIAuthentication.html">KBIAuthentication</a> authentication mechanism.
 * 
 * @author $author$
 */
public interface KBIRequestHandler {
	/**
	 * Called by the <em>keyboard-interactive</em> authentication mechanism when
	 * the server requests information from the user. Each prompt should be
	 * displayed to the user with their response recorded within the prompt
	 * object.
	 * 
	 * @param name
	 * @param instruction
	 * @param prompts
	 * @return <em>true</em> if the user entered the prompts, or <em>false</em>
	 *         if the user cancelled the authentication attempt.
	 */
	public boolean showPrompts(String name, String instruction,
			KBIPrompt[] prompts);
}

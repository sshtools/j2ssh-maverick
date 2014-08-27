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
package com.sshtools.events;


/**
 * This is a wrapper class.  
 * It allows all log.info and log.debug calls to be replaced with its methods.
 * When a Log* method is called it fires a new J2SSH event of the appropriate log type, and adds the message as an attribute.
 * If a throwable object is passed as a parameter, this is added as an attribute of event fired.
 * @author david
 *
 */
public final class EventLog {
	
	/**
	 * A normal log event
	 * @param source
	 * @param message
	 */
	public static void LogEvent(Object source, String message) { 
		EventServiceImplementation.getInstance().fireEvent((new Event(source,J2SSHEventCodes.EVENT_LOG,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_LOG_MESSAGE, message));
	}

	/**
	 * An error log event
	 * @param source
	 * @param message
	 */
	public static void LogErrorEvent(Object source, String message) { 
		EventServiceImplementation.getInstance().fireEvent((new Event(source,J2SSHEventCodes.EVENT_ERROR_LOG,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_LOG_MESSAGE, message));
	}
	
	/**
	 * A debug event
	 * @param source
	 * @param message
	 */
	public static void LogDebugEvent(Object source, String message) { 
		EventServiceImplementation.getInstance().fireEvent((new Event(source,J2SSHEventCodes.EVENT_DEBUG_LOG,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_LOG_MESSAGE, message));
	}
	
	/**
	 * An exception event
	 * @param source
	 * @param message
	 * @param t
	 */
	public static void LogEvent(Object source, String message, Throwable t) { 
		EventServiceImplementation.getInstance().fireEvent((new Event(source,J2SSHEventCodes.EVENT_EXCEPTION_LOG,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_LOG_MESSAGE, message).addAttribute(J2SSHEventCodes.ATTRIBUTE_THROWABLE, t));
	}
}

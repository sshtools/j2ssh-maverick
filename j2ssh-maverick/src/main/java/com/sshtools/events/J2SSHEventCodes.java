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
package com.sshtools.events;

/**
 * List of unique J2SSH Event codes
 * 
 * @author david
 * 
 */
public class J2SSHEventCodes {
	// J2SSHEventCodes.ATTRIBUTE_
	// EventServiceImplementation.getInstance().fireEvent(Thread.currentThread().getName(),
	// new J2SSHEvent(this,J2SSHEventCodes.EVENT_,true));
	// EventServiceImplementation.getInstance().fireEvent(Thread.currentThread().getName(),
	// (new
	// J2SSHEvent(this,J2SSHEventCodes.EVENT_,true)).addAttribute(J2SSHEventCodes.ATTRIBUTE_,
	// ));

	// attributes
	public static final String ATTRIBUTE_HOST_KEY = "HOST_KEY";

	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_KEY_EXCHANGE = "USING_KEY_EXCHANGE";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_PUBLICKEY = "USING_PUBLICKEY";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_CS_CIPHER = "USING_CS_CIPHER";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_SC_CIPHER = "USING_SC_CIPHERC";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_CS_MAC = "USING_CS_MAC";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_SC_MAC = "USING_SC_MAC";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_CS_COMPRESSION = "USING_CS_COMPRESSION";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_USING_SC_COMPRESSION = "USING_SC_COMPRESSION";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_KEY_EXCHANGES = "REMOTE_KEY_EXCHANGES";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_PUBLICKEYS = "REMOTE_PUBLICKEYS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_CIPHERS_CS = "REMOTE_CIPHERS_CS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_CIPHERS_SC = "REMOTE_CIPHERS_SC";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_CS_MACS = "REMOTE_CS_MACS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_SC_MACS = "REMOTE_SC_MACS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_CS_COMPRESSIONS = "REMOTE_CS_COMPRESSIONS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_REMOTE_SC_COMPRESSIONS = "REMOTE_SC_COMPRESSIONS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_KEY_EXCHANGES = "LOCAL_KEY_EXCHANGES";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_PUBLICKEYS = "LOCAL_PUBLICKEYS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_CIPHERS_CS = "LOCAL_CIPHERS_CS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_CIPHERS_SC = "LOCAL_CIPHERS_SC";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_CS_MACS = "LOCAL_CS_MACS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_SC_MACS = "LOCAL_SC_MACS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_CS_COMPRESSIONS = "LOCAL_CS_COMPRESSIONS";
	/** algorithm negotiation preferences */
	public static final String ATTRIBUTE_LOCAL_SC_COMPRESSIONS = "LOCAL_SC_COMPRESSIONS";

	/**
	 * This attribute is the key for the log message previously passes to
	 * log.info()/log.debug() calls
	 */
	public static final String ATTRIBUTE_LOG_MESSAGE = "LOG_MESSAGE";
	/**
	 * This attribute is the key for the throwable object previously passed in
	 * some log.info() calls.
	 */
	public static final String ATTRIBUTE_THROWABLE = "THROWABLE";

	public static final String ATTRIBUTE_AUTHENTICATION_METHODS = "AUTHENTICATION_METHODS";

	public static final String ATTRIBUTE_FORWARDING_TUNNEL_ENTRANCE = "FORWARDING_TUNNEL_ENTRANCE";
	public static final String ATTRIBUTE_FORWARDING_TUNNEL_EXIT = "FORWARDING_TUNNEL_EXIT";

	public static final String ATTRIBUTE_FILE_NAME = "FILE_NAME";
	public static final String ATTRIBUTE_FILE_NEW_NAME = "FILE_NEW_NAME";
	public static final String ATTRIBUTE_DIRECTORY_PATH = "DIRECTORY_PATH";
	public static final String ATTRIBUTE_COMMAND = "COMMAND";

	public static final String ATTRIBUTE_IP = "IP";

	public static final String ATTRIBUTE_NUMBER_OF_CONNECTIONS = "NUMBER_OF_CONNECTIONS";

	public static final String ATTRIBUTE_LOCAL_COMPONENT_LIST = "LOCAL_COMPONENT_LIST";
	public static final String ATTRIBUTE_REMOTE_COMPONENT_LIST = "REMOTE_COMPONENT_LIST";
	
	// events
	public static final int EVENT_HOSTKEY_RECEIVED = 0;
	public static final int EVENT_HOSTKEY_REJECTED = 1;
	public static final int EVENT_HOSTKEY_ACCEPTED = 2;

	public static final int EVENT_KEY_EXCHANGE_INIT = 3;
	public static final int EVENT_KEY_EXCHANGE_FAILURE = 4;
	public static final int EVENT_KEY_EXCHANGE_COMPLETE = 5;

	public static final int EVENT_AUTHENTICATION_METHODS_RECEIVED = 11;

	public static final int EVENT_USERAUTH_SUCCESS = 13;
	public static final int EVENT_USERAUTH_FAILURE = 14;
	public static final int EVENT_USERAUTH_FURTHER_AUTHENTICATION_REQUIRED = 15;

	public static final int EVENT_FORWARDING_LOCAL_STARTED = 16;
	public static final int EVENT_FORWARDING_REMOTE_STARTED = 17;
	public static final int EVENT_FORWARDING_LOCAL_STOPPED = 18;
	public static final int EVENT_FORWARDING_REMOTE_STOPPED = 19;

	public static final int EVENT_DISCONNECTED = 20;
	public static final int EVENT_RECEIVED_DISCONNECT = 21;

	public static final int EVENT_SHELL_SESSION_STARTED = 23;
	public static final int EVENT_SHELL_SESSION_FAILED_TO_START = 24;
	public static final int EVENT_SHELL_COMMAND = 30;
	public static final int EVENT_SUBSYSTEM_STARTED = 1001;

	public static final int EVENT_SFTP_SESSION_STARTED = 22;
	public static final int EVENT_SFTP_SESSION_STOPPED = 31;
	public static final int EVENT_SFTP_FILE_CLOSED = 25;
	public static final int EVENT_SFTP_FILE_OPENED = 26;
	public static final int EVENT_SFTP_FILE_RENAMED = 27;
	public static final int EVENT_SFTP_FILE_DELETED = 28;
	public static final int EVENT_SFTP_DIRECTORY_DELETED = 29;
	public static final int EVENT_FAILED_TO_NEGOTIATE_TRANSPORT_COMPONENT = 32;

	public static final int EVENT_CONNECTION_ATTEMPT = 100;
	public static final int EVENT_REACHED_CONNECTION_LIMIT = 101;

}

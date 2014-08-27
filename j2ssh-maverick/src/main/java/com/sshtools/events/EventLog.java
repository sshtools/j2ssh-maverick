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

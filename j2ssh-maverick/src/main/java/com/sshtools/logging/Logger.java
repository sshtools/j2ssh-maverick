package com.sshtools.logging;

public interface Logger {

	boolean isLevelEnabled(LoggerLevel level);

	void log(LoggerLevel level, Object source, String msg);

	void log(LoggerLevel level, Object source, String msg, Throwable t);

}

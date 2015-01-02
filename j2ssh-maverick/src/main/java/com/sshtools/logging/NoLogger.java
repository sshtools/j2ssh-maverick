package com.sshtools.logging;

public class NoLogger implements Logger {

	public boolean isLevelEnabled(LoggerLevel level) {
		return false;
	}

	public void log(LoggerLevel level, Object source, String msg) {

	}

	public void log(LoggerLevel level, Object source, String msg, Throwable t) {

	}

}

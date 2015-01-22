package com.sshtools.logging;

public class SimpleLogger implements Logger {

	LoggerLevel level; 
	
	public SimpleLogger(LoggerLevel level) {
		this.level = level;
	}
	
	public boolean isLevelEnabled(LoggerLevel level) {
		return this.level.ordinal() >= level.ordinal();
	}

	public void log(LoggerLevel level, Object source, String msg) {
		System.out.println(level.toString() + ": " + msg);
	}

	public void log(LoggerLevel level, Object source, String msg, Throwable t) {
		System.out.println(level.toString() + ": " + msg);
		t.printStackTrace();
	}

}

package com.sshtools.logging;

public class LoggerFactory {

	static Logger logger = new NoLogger();

	static boolean enabled = false;

	public static void setInstance(Logger logger) {
		LoggerFactory.logger = logger;
		enabled = true;
	}

	public static Logger getInstance() {
		return logger;
	}
	
	public static boolean isEnabled() {
		return enabled;
	}

	public static void enable() {
		enabled = true;
	}

	public static void disable() {
		enabled = false;
	}
}

package com.sshtools.events;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Hashtable;


/**
 * Time saving class for the LoggingMaverickListener class that sets the message code for each event to its event code field name.
 * @author david
 *
 */
public final class J2SSHEventMessages {
	public static Hashtable<Object,String> messageCodes=new Hashtable<Object,String>();
	public static Hashtable<Object,String> messageAttributes=new Hashtable<Object,String>();
	
	static {
		Class<?> mavevent=J2SSHEventCodes.class;
		Field[] fields=mavevent.getFields();
		for(int i=0;i<fields.length;i++) {
			int modifiers=fields[i].getModifiers();
			if(Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
				try {
					String fieldName=fields[i].getName();
					if(fieldName.startsWith("EVENT_")) {
						messageCodes.put(fields[i].get(null), fieldName.substring(6));
					} else {
						messageAttributes.put(fields[i].get(null), fieldName.substring(10));
					}
				} catch (IllegalArgumentException e) {
				} catch (IllegalAccessException e) {
				}
			}
		}
	}
}

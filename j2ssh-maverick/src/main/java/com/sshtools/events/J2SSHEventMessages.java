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
package com.sshtools.events;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Hashtable;

/**
 * Time saving class for the LoggingMaverickListener class that sets the message
 * code for each event to its event code field name.
 * 
 * @author david
 * 
 */
public final class J2SSHEventMessages {
	public static Hashtable<Object, String> messageCodes = new Hashtable<Object, String>();
	public static Hashtable<Object, String> messageAttributes = new Hashtable<Object, String>();

	static {
		Class<?> mavevent = J2SSHEventCodes.class;
		Field[] fields = mavevent.getFields();
		for (int i = 0; i < fields.length; i++) {
			int modifiers = fields[i].getModifiers();
			if (Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
				try {
					String fieldName = fields[i].getName();
					if (fieldName.startsWith("EVENT_")) {
						messageCodes.put(fields[i].get(null),
								fieldName.substring(6));
					} else {
						messageAttributes.put(fields[i].get(null),
								fieldName.substring(10));
					}
				} catch (IllegalArgumentException e) {
				} catch (IllegalAccessException e) {
				}
			}
		}
	}
}

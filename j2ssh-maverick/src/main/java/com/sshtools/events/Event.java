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

import java.util.Enumeration;
import java.util.Hashtable;

/**
 * Superclass of all events that may be fired during the life of J2SSH.
 * <p>
 * All events have the following attributes in common :-
 * <ul>
 * <li>Event code. This is an <code>int</code> and must be unique across the
 * whole of J2SSH.</li>
 * <li>State. A boolean specifying whether the event is the result of a
 * successful operation or a failed one.</li>
 * </ul>
 * <p>
 */
public class Event extends EventObject {

	private final int id;
	private final boolean state;
	private final Hashtable<String, Object> eventAttributes = new Hashtable<String, Object>();

	/**
	 * @param source
	 *            source of event
	 * @param id
	 *            event code
	 * @param boolean state true=successful false=unsuccessful
	 */
	public Event(Object source, int id, boolean state) {
		super(source);
		this.id = id;
		this.state = state;
	}

	/**
	 * Get the unique event id
	 * 
	 * @return unique event id
	 */
	public int getId() {
		return id;
	}

	/**
	 * Get the event state. May be one of {@link #STATE_SUCCESSFUL} or
	 * {@link #STATE_UNSUCCESSFUL}.
	 * 
	 * @return event state
	 */
	public boolean getState() {
		return state;
	}

	/**
	 * Get the value of an event attribute
	 * 
	 * @param key
	 *            key of event
	 * @return value
	 */
	public Object getAttribute(String key) {
		return eventAttributes.get(key);
	}

	public String getAllAttributes() {
		StringBuffer buff = new StringBuffer();
		for (Enumeration<String> elements = eventAttributes.keys(); elements
				.hasMoreElements();) {
			String parameter = (String) elements.nextElement();
			String value = eventAttributes.get(parameter).toString();
			buff.append("|\r\n");
			buff.append(parameter);
			buff.append(" = ");
			buff.append(value);
		}

		return buff.toString();
	}

	/**
	 * Add an attribute to the event
	 * 
	 * @param key
	 *            key of attribute
	 * @param String
	 *            value of attribute
	 * @return this object, to allow event attribute chains
	 */
	public Event addAttribute(String key, Object value) {
		eventAttributes.put(key, (value == null ? "null" : value));
		return this;
	}

}
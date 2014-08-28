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

package com.sshtools.sftp;

import java.io.IOException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.sshtools.util.ByteArrayReader;
import com.sshtools.util.ByteArrayWriter;
import com.sshtools.util.UnsignedInteger32;
import com.sshtools.util.UnsignedInteger64;

/**
 * This class represents the ATTRS structure defined in the draft-ietf-secsh-filexfer-02.txt which
 * is used by the protocol to store file attribute information.
 *
 * @author Lee David Painter
 */
public class SftpFileAttributes {

  static final int SSH_FILEXFER_ATTR_SIZE =            0x00000001;
  // This is only used for version <= 3
  static final long SSH_FILEXFER_ATTR_UIDGID =          0x00000002;
  static final long SSH_FILEXFER_ATTR_PERMISSIONS =     0x00000004;
  static final long SSH_FILEXFER_ATTR_ACCESSTIME =      0x00000008;
  static final long SSH_FILEXFER_ATTR_CREATETIME =      0x00000010;
  static final long SSH_FILEXFER_ATTR_MODIFYTIME =      0x00000020;
  static final long SSH_FILEXFER_ATTR_ACL =             0x00000040;
  static final long SSH_FILEXFER_ATTR_OWNERGROUP =      0x00000080;
  static final long SSH_FILEXFER_ATTR_SUBSECOND_TIMES = 0x00000100;
  static final long SSH_FILEXFER_ATTR_EXTENDED =        0x80000000;

  public static final int SSH_FILEXFER_TYPE_REGULAR = 1;
  public static final int SSH_FILEXFER_TYPE_DIRECTORY = 2;
  public static final int SSH_FILEXFER_TYPE_SYMLINK = 3;
  public static final int SSH_FILEXFER_TYPE_SPECIAL = 4;
  public static final int SSH_FILEXFER_TYPE_UNKNOWN = 5;

  private Vector<ACL> acls = new Vector<ACL>();
  private Hashtable<String, byte[]> extendedAttributes = new Hashtable<String, byte[]>();

  // Posix stats

  /** Permissions flag: Format mask constant can be used to mask off a file type from the mode. */
  public static final int S_IFMT = 0xF000;

  /** Permissions flag: Identifies the file as a socket */
  public static final int S_IFSOCK = 0xC000;

  /** Permissions flag: Identifies the file as a symbolic link */
  public static final int S_IFLNK = 0xA000;

  /** Permissions flag: Identifies the file as a regular file */
  public static final int S_IFREG = 0x8000;

  /** Permissions flag: Identifies the file as a block special file */
  public static final int S_IFBLK = 0x6000;

  /** Permissions flag: Identifies the file as a directory */
  public static final int S_IFDIR = 0x4000;

  /** Permissions flag: Identifies the file as a character device */
  public static final int S_IFCHR = 0x2000;

  /** Permissions flag: Identifies the file as a pipe */
  public static final int S_IFIFO = 0x1000;

  /** Permissions flag: Bit to determine whether a file is executed as the owner */
  public final static int S_ISUID = 0x800;

  /** Permissions flag: Bit to determine whether a file is executed as the group owner */
  public final static int S_ISGID = 0x400;

  /** Permissions flag: Permits the owner of a file to read the file. */
  public final static int S_IRUSR = 0x100;

  /** Permissions flag: Permits the owner of a file to write to the file. */
  public final static int S_IWUSR = 0x80;

  /** Permissions flag: Permits the owner of a file to execute the file or to search the file's directory. */
  public final static int S_IXUSR = 0x40;

  /** Permissions flag: Permits a file's group to read the file. */
  public final static int S_IRGRP = 0x20;

  /** Permissions flag: Permits a file's group to write to the file. */
  public final static int S_IWGRP = 0x10;

  /** Permissions flag: Permits a file's group to execute the file or to search the file's directory. */
  public final static int S_IXGRP = 0x08;

  /** Permissions flag: Permits others to read the file. */
  public final static int S_IROTH = 0x04;

  /** Permissions flag: Permits others to write to the file. */
  public final static int S_IWOTH = 0x02;

  /** Permissions flag: Permits others to execute the file or to search the file's directory. */
  public final static int S_IXOTH = 0x01;

  int version = 3;
  long flags = 0x0000000;
  int type; // Version 4 only
  UnsignedInteger64 size = null;
  String uid = null;
  String gid = null;
  UnsignedInteger32 permissions = null;
  UnsignedInteger64 atime = null;
  UnsignedInteger32 atime_nano = null;
  UnsignedInteger64 createtime = null;
  UnsignedInteger32 createtime_nano = null;
  UnsignedInteger64 mtime = null;
  UnsignedInteger32 mtime_nano = null;
  String username;
  String group;

  char[] types = {
      'p', 'c', 'd', 'b', '-', 'l', 's', };

  SftpSubsystemChannel sftp;
  /**
   * Creates a new FileAttributes object.
   */
  public SftpFileAttributes(SftpSubsystemChannel sftp, int type) {
      this.sftp = sftp;
      this.version = sftp.getVersion();
      this.type = type;

  }

  public int getType() {
      return type;
  }

  /**
 * @param sftp
 * @param bar
 * @throws IOException
 */
public SftpFileAttributes(SftpSubsystemChannel sftp, ByteArrayReader bar) throws IOException {
    this.sftp = sftp;
    this.version = sftp.getVersion();

    if(bar.available() >= 4)
    	flags = bar.readInt();

    // Work out the type from the permissions field later if we're not using version
    // 4 of the protocol
    if(version > 3) {
        // Get the type if were using version 4+ of the protocol
    	if(bar.available() > 0)
    		type = bar.read();
    }

    //if ATTR_SIZE flag is set then read size
    if (isFlagSet(SSH_FILEXFER_ATTR_SIZE) && bar.available() >= 8) {
      byte[] raw = new byte[8];
      bar.read(raw);
      size = new UnsignedInteger64(raw);
    }

    if (version <= 3 && isFlagSet(SSH_FILEXFER_ATTR_UIDGID) && bar.available() >= 8) {
   	
      uid = String.valueOf(bar.readInt());
      gid = String.valueOf(bar.readInt());
    } else if(version > 3 && isFlagSet(SSH_FILEXFER_ATTR_OWNERGROUP) && bar.available() >= 8) {
      uid = bar.readString(sftp.getCharsetEncoding());
      gid = bar.readString(sftp.getCharsetEncoding());
    }

    if (isFlagSet(SSH_FILEXFER_ATTR_PERMISSIONS) && bar.available() >= 4) {
      permissions = new UnsignedInteger32(bar.readInt());
    }

    if (version <= 3 && isFlagSet(SSH_FILEXFER_ATTR_ACCESSTIME) && bar.available() >= 8) {
      atime = new UnsignedInteger64(bar.readInt());
      mtime = new UnsignedInteger64(bar.readInt());
    } else if(version > 3  && bar.available() > 0) {
      if(isFlagSet(SSH_FILEXFER_ATTR_ACCESSTIME) && bar.available() >= 8)
          atime = bar.readUINT64();
      if(isFlagSet(SSH_FILEXFER_ATTR_SUBSECOND_TIMES) && bar.available() >= 4) {
          atime_nano = bar.readUINT32();
      }
    }

    if(version > 3 && bar.available() > 0) {
        if(isFlagSet(SSH_FILEXFER_ATTR_CREATETIME) && bar.available() >= 8)
          createtime = bar.readUINT64();
        if(isFlagSet(SSH_FILEXFER_ATTR_SUBSECOND_TIMES) && bar.available() >= 4)
            createtime_nano = bar.readUINT32();
    }

    if(version > 3 && bar.available() > 0) {
        if(isFlagSet(SSH_FILEXFER_ATTR_MODIFYTIME) && bar.available() >= 8)
          mtime = bar.readUINT64();
        if(isFlagSet(SSH_FILEXFER_ATTR_SUBSECOND_TIMES) && bar.available() >= 4)
          mtime_nano = bar.readUINT32();
    }

    // We are currently ignoring ACL and extended attributes
    if(version > 3 && isFlagSet(SSH_FILEXFER_ATTR_ACL) && bar.available() >= 4) {

        int length = (int) bar.readInt();
        
        if(length > 0 && bar.available() >= length) {
	        int count = (int)bar.readInt();
	        for(int i = 0;i<count;i++) {
	
	            acls.addElement(new ACL((int)bar.readInt(),
	                                    (int)bar.readInt(),
	                                    (int)bar.readInt(),
	                                    bar.readString()));
	        }
        }
    }

    if(version >= 3 && isFlagSet(SSH_FILEXFER_ATTR_EXTENDED) && bar.available() >= 4) {
        int count = (int)bar.readInt();
        //read each extended attribute
        for(int i=0;i<count;i++) {
        	if(bar.available() >= 8) {
	            extendedAttributes.put(bar.readString(),
	                                   bar.readBinaryString());
        	}
        }
    }
  }

  /**
   * Get the UID of the owner.
   *
   * @return String
   */
  public String getUID() {
	if(username != null) {
		return username;
	}
    if (uid != null) {
      return uid;
    }
	return "";
  }

  /**
   * Set the UID of the owner.
   *
   * @param uid
   */
  public void setUID(String uid) {
      if(version > 3) {
          flags |= SSH_FILEXFER_ATTR_OWNERGROUP;
      } else
        flags |= SSH_FILEXFER_ATTR_UIDGID;
    this.uid = uid;
  }

  /**
   * Set the GID of this file.
   *
   * @param gid
   */
  public void setGID(String gid) {

    if(version > 3) {
        flags |= SSH_FILEXFER_ATTR_OWNERGROUP;
    } else
        flags |= SSH_FILEXFER_ATTR_UIDGID;
    this.gid = gid;
  }

  /**
   * Get the GID of this file.
   *
   * @return String
   */
  public String getGID() {
	 if(group != null) {
		 return group;
	 }
    if (gid != null) {
      return gid;
    }
	return "";
  }

  public boolean hasUID() {
      return uid != null;
  }

  public boolean hasGID() {
      return gid != null;
  }
  
  /**
   * Set the size of the file.
   *
   * @param size
   */
  public void setSize(UnsignedInteger64 size) {
    this.size = size;

    // Set the flag
    if (size != null) {
      flags |= SSH_FILEXFER_ATTR_SIZE;
    }
    else {
      flags ^= SSH_FILEXFER_ATTR_SIZE;
    }
  }

  /**
   *
   * Get the size of the file.
   *
   * @return UnsignedInteger64
   */
  public UnsignedInteger64 getSize() {
    if (size != null) {
      return size;
    }
	return new UnsignedInteger64("0");
  }

  public boolean hasSize() {
      return size != null;
  }
  
  /**
   * Set the permissions of the file. This value should be a valid mask of the
   * permissions flags defined within this class.
   */
  public void setPermissions(UnsignedInteger32 permissions) {
    this.permissions = permissions;

    // Set the flag
    if (permissions != null) {
      flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
    }
    else {
      flags ^= SSH_FILEXFER_ATTR_PERMISSIONS;
    }
  }

  /**
   * Set permissions given a UNIX style mask, for example '0644'
   *
   * @param mask mask
   *
   * @throws IllegalArgumentException if badly formatted string
   */
  public void setPermissionsFromMaskString(String mask) {
    if (mask.length() != 4) {
      throw new IllegalArgumentException("Mask length must be 4");
    }

    try {
      setPermissions(new UnsignedInteger32(String.valueOf(
          Integer.parseInt(mask, 8))));
    }
    catch (NumberFormatException nfe) {
      throw new IllegalArgumentException(
          "Mask must be 4 digit octal number.");
    }
  }

  /**
   * Set the permissions given a UNIX style umask, for example '0022' will
   * result in 0022 ^ 0777.
   *
   * @param umask
   * @throws IllegalArgumentException if badly formatted string
   */
  public void setPermissionsFromUmaskString(String umask) {
    if (umask.length() != 4) {
      throw new IllegalArgumentException("umask length must be 4");
    }

    try {
      setPermissions(new UnsignedInteger32(
          String.valueOf(Integer.parseInt(umask, 8) ^ 0777)));
    }
    catch (NumberFormatException ex) {
      throw new IllegalArgumentException("umask must be 4 digit octal number");
    }
  }

  /**
   * Set the permissions from a string in the format "rwxr-xr-x"
   *
   * @param newPermissions
   */
  public void setPermissions(String newPermissions) {
    int cp = 0;

    if (permissions != null) {
      cp = cp
          | ( ( (permissions.longValue() & S_IFMT) == S_IFMT) ? S_IFMT : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFSOCK) == S_IFSOCK) ? S_IFSOCK
             : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFLNK) == S_IFLNK) ? S_IFLNK : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFREG) == S_IFREG) ? S_IFREG : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFBLK) == S_IFBLK) ? S_IFBLK : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFDIR) == S_IFDIR) ? S_IFDIR : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFCHR) == S_IFCHR) ? S_IFCHR : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_IFIFO) == S_IFIFO) ? S_IFIFO : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_ISUID) == S_ISUID) ? S_ISUID : 0);
      cp = cp
          | ( ( (permissions.longValue() & S_ISGID) == S_ISGID) ? S_ISGID : 0);
    }

    int len = newPermissions.length();

    if (len >= 1) {
      cp = cp
          |
          ( (newPermissions.charAt(0) == 'r') ? SftpFileAttributes.S_IRUSR : 0);
    }

    if (len >= 2) {
      cp = cp
          |
          ( (newPermissions.charAt(1) == 'w') ? SftpFileAttributes.S_IWUSR : 0);
    }

    if (len >= 3) {
      cp = cp
          |
          ( (newPermissions.charAt(2) == 'x') ? SftpFileAttributes.S_IXUSR : 0);
    }

    if (len >= 4) {
      cp = cp
          |
          ( (newPermissions.charAt(3) == 'r') ? SftpFileAttributes.S_IRGRP : 0);
    }

    if (len >= 5) {
      cp = cp
          |
          ( (newPermissions.charAt(4) == 'w') ? SftpFileAttributes.S_IWGRP : 0);
    }

    if (len >= 6) {
      cp = cp
          |
          ( (newPermissions.charAt(5) == 'x') ? SftpFileAttributes.S_IXGRP : 0);
    }

    if (len >= 7) {
      cp = cp
          |
          ( (newPermissions.charAt(6) == 'r') ? SftpFileAttributes.S_IROTH : 0);
    }

    if (len >= 8) {
      cp = cp
          |
          ( (newPermissions.charAt(7) == 'w') ? SftpFileAttributes.S_IWOTH : 0);
    }

    if (len >= 9) {
      cp = cp
          |
          ( (newPermissions.charAt(8) == 'x') ? SftpFileAttributes.S_IXOTH : 0);
    }

    setPermissions(new UnsignedInteger32(cp));
  }

  /**
   * Get the current permissions value.
   *
   * @return UnsignedInteger32
   */
  public UnsignedInteger32 getPermissions() {
      if(permissions!=null)
          return permissions;
	return new UnsignedInteger32(0);
  }

  /**
   * Set the last access and last modified times. These times are represented by integers containing
   * the number of seconds from Jan 1, 1970 UTC. NOTE: You should divide any value returned from
   * Java's System.currentTimeMillis() method by 1000 to set the correct times as this returns the time
   * in milliseconds from Jan 1, 1970 UTC.
   *
   * @param atime
   * @param mtime
   */
  public void setTimes(UnsignedInteger64 atime, UnsignedInteger64 mtime) {
    this.atime = atime;
    this.mtime = mtime;

    // Set the flag
    if (atime != null) {
      flags |= SSH_FILEXFER_ATTR_ACCESSTIME;
    }
    else {
      flags ^= SSH_FILEXFER_ATTR_ACCESSTIME;
    }
  }

  /**
   * Get the last accessed time. This integer value represents the number of seconds from Jan 1, 1970 UTC. When
   * using with Java Date/Time classes you should multiply this value by 1000 as Java uses the time in
   * milliseconds rather than seconds.
   *
   * @return UnsignedInteger64
   */
  public UnsignedInteger64 getAccessedTime() {
    return atime;
  }

  /**
   * Get the last modified time. This integer value represents the number of seconds from Jan 1, 1970 UTC. When
   * using with Java Date/Time classes you should multiply this value by 1000 as Java uses the time in
   * milliseconds rather than seconds.
   *
   * @return UnsignedInteger64
   */
  public UnsignedInteger64 getModifiedTime() {
    if (mtime != null) {
      return mtime;
    }
	return new UnsignedInteger64(0);
  }
  
  /**
   * Returns the modified date/time as a Java Date object.
   * @return
   */
  public Date getModifiedDateTime(){ 
	  
	  long time = 0;
	  
	  if(mtime!=null) {
		  time = mtime.longValue() * 1000;
	  }
	  
	  if(mtime_nano!=null) {
		  time += (mtime_nano.longValue() / 1000000);
	  }
	  return new Date(time);
  }

  /**
   * Returns the creation date/time as a Java Date object. 
   * @return
   */
  public Date getCreationDateTime(){ 
	  
	  long time = 0;
	  
	  if(createtime!=null) {
		  time = createtime.longValue() * 1000;
	  }
	  
	  if(createtime_nano!=null) {
		  time += (createtime_nano.longValue() / 1000000);
	  }
	  return new Date(time);
  }

  /**
   * Returns the last accessed date/time as a Java Date object. 
   * @return
   */
  public Date getAccessedDateTime(){ 
	  
	  long time = 0;
	  
	  if(atime!=null) {
		  time = atime.longValue() * 1000;
	  }
	  
	  if(atime!=null) {
		  time += (atime_nano.longValue() / 1000000);
	  }
	  return new Date(time);
  }
  
  /**
   * Get the creation time of this file. This is only supported for SFTP
   * protocol version 4 and above; if called when protocol revision is lower
   * this method will return a zero value.
   *
   * @return UnsignedInteger64
   */
  public UnsignedInteger64 getCreationTime() {
      if(createtime != null)
          return createtime;
	return new UnsignedInteger64(0);
  }

  /**
   * Determine if a permissions flag is set.
   *
   * @param flag
   *
   * @return boolean
   */
  public boolean isFlagSet(long flag) {
    return ( (flags & (flag & 0xFFFFFFFFL)) == (flag & 0xFFFFFFFFL));
  }

  /**
   * Returns a formatted byte array suitable for encoding into SFTP subsystem messages.
   *
   * @return byte[]
   *
   * @throws IOException
   */
  public byte[] toByteArray() throws IOException {
    ByteArrayWriter baw = new ByteArrayWriter();

    try {
	    baw.writeInt(flags);
	
	    if(version > 3)
	        baw.write(type);
	
	    if (isFlagSet(SSH_FILEXFER_ATTR_SIZE)) {
	      baw.write(size.toByteArray());
	    }
	
	    if (version <= 3 && isFlagSet(SSH_FILEXFER_ATTR_UIDGID)) {
	      if (uid != null) {
	          try {
	              baw.writeInt(Long.parseLong(uid));
	          } catch (NumberFormatException ex) {
	              baw.writeInt(0);
	          }
	      }
	      else {
	        baw.writeInt(0);
	      }
	
	      if (gid != null) {
	          try {
	              baw.writeInt(Long.parseLong(gid));
	          } catch (NumberFormatException ex) {
	              baw.writeInt(0);
	          }
	      }
	      else {
	        baw.writeInt(0);
	      }
	    } else if(version > 3 && isFlagSet(SSH_FILEXFER_ATTR_OWNERGROUP)) {
	        if(uid!=null)
	            baw.writeString(uid, sftp.getCharsetEncoding());
	        else
	            baw.writeString("");
	
	        if(gid!=null)
	            baw.writeString(gid, sftp.getCharsetEncoding());
	        else
	            baw.writeString("");
	    }
	
	
	    if (isFlagSet(SSH_FILEXFER_ATTR_PERMISSIONS)) {
	      baw.writeInt(permissions.longValue());
	    }
	
	    if (version <= 3 && isFlagSet(SSH_FILEXFER_ATTR_ACCESSTIME)) {
	      baw.writeInt(atime.longValue());
	      baw.writeInt(mtime.longValue());
	    } else if(version > 3) {
	
	        if(isFlagSet(SSH_FILEXFER_ATTR_ACCESSTIME)) {
	            baw.writeUINT64(atime);
	        }
	
	        if(isFlagSet(SSH_FILEXFER_ATTR_SUBSECOND_TIMES)) {
	            baw.writeUINT32(atime_nano);
	        }
	
	        if(isFlagSet(SSH_FILEXFER_ATTR_CREATETIME)) {
	            baw.writeUINT64(createtime);
	        }
	
	        if(isFlagSet(SSH_FILEXFER_ATTR_SUBSECOND_TIMES)) {
	            baw.writeUINT32(createtime_nano);
	        }
	
	        if(isFlagSet(SSH_FILEXFER_ATTR_MODIFYTIME)) {
	            baw.writeUINT64(mtime);
	        }
	
	        if(isFlagSet(SSH_FILEXFER_ATTR_SUBSECOND_TIMES)) {
	            baw.writeUINT32(mtime_nano);
	        }
	
	
	    }
	
	    if(isFlagSet(SSH_FILEXFER_ATTR_ACL)) {
	        ByteArrayWriter tmp = new ByteArrayWriter();
	        
	        try {
		        Enumeration<ACL> e = acls.elements();
		        tmp.writeInt(acls.size());
		        while(e.hasMoreElements()) {
		            ACL acl = e.nextElement();
		            tmp.writeInt(acl.getType());
		            tmp.writeInt(acl.getFlags());
		            tmp.writeInt(acl.getMask());
		            tmp.writeString(acl.getWho());
		        }
		
		        baw.writeBinaryString(tmp.toByteArray());
	        } finally {
	        	tmp.close();
	        }
	    }
	
	    if(isFlagSet(SSH_FILEXFER_ATTR_EXTENDED)) {
	        baw.writeInt(extendedAttributes.size());
	        Enumeration<String> e = extendedAttributes.keys();
	        while(e.hasMoreElements()) {
	            String key = e.nextElement();
	            baw.writeString(key);
	            baw.writeBinaryString(extendedAttributes.get(key));
	        }
	    }
	
	    return baw.toByteArray();
    } finally {
  			try {
  				baw.close();
  			} catch (IOException e) {
  			}
    }
  }

  private int octal(int v, int r) {
    v >>>= r;

    return ( ( (v & 0x04) != 0) ? 4 : 0) + ( ( (v & 0x02) != 0) ? 2 : 0)
        + + ( ( (v & 0x01) != 0) ? 1 : 0);
  }

  private String rwxString(int v, int r) {
    v >>>= r;

    String rwx = ( ( ( (v & 0x04) != 0) ? "r" : "-")
                  + ( ( (v & 0x02) != 0) ? "w" : "-"));

    if ( ( (r == 6) && ( (permissions.longValue() & S_ISUID) == S_ISUID))
        || ( (r == 3) && ( (permissions.longValue() & S_ISGID) == S_ISGID))) {
      rwx += ( ( (v & 0x01) != 0) ? "s" : "S");
    }
    else {
      rwx += ( ( (v & 0x01) != 0) ? "x" : "-");
    }

    return rwx;
  }

  /**
   *
   * Returns a formatted permissions string.
   *
   * @return String
   */
  public String getPermissionsString() {
    if (permissions != null) {
      StringBuffer str = new StringBuffer();
      boolean has_ifmt = ((int) permissions.longValue() & S_IFMT) > 0;
      if(has_ifmt)
    	  str.append(types[(int) (permissions.longValue() & S_IFMT) >>> 13]);
      else
    	  str.append('-');
      str.append(rwxString( (int) permissions.longValue(), 6));
      str.append(rwxString( (int) permissions.longValue(), 3));
      str.append(rwxString( (int) permissions.longValue(), 0));

      return str.toString();
    }
	return "";
  }

  /**
   * Return the UNIX style mode mask
   *
   * @return mask
   */
  public String getMaskString() {
    StringBuffer buf = new StringBuffer();

    if(permissions!=null) {
	    int i = (int) permissions.longValue();
	    buf.append('0');
	    buf.append(octal(i, 6));
	    buf.append(octal(i, 3));
	    buf.append(octal(i, 0));
    } else {
    	buf.append("----");
    }
    return buf.toString();
  }

  /**
   * Determine whether these attributes refer to a directory
   *
   * @return boolean
   */
  public boolean isDirectory() {
      if (sftp.getVersion() > 3) {
          return type == SSH_FILEXFER_TYPE_DIRECTORY;
      } else if (permissions != null
                 && (permissions.longValue() & SftpFileAttributes.S_IFDIR)
                 == SftpFileAttributes.S_IFDIR) {
          return true;
      } else {
          return false;
      }
  }

  /**
   *
   * Determine whether these attributes refer to a file.
   * @return boolean
   */
  public boolean isFile() {

      if (sftp.getVersion() > 3) {
            return type == SSH_FILEXFER_TYPE_REGULAR;
        } else if (permissions != null && (permissions.longValue() & SftpFileAttributes.S_IFREG) ==
      SftpFileAttributes.S_IFREG) {
      return true;
    }
    else {
      return false;
    }
  }

  /**
   * Determine whether these attributes refer to a symbolic link.
   *
   * @return boolean
   */
  public boolean isLink() {

    if (sftp.getVersion() > 3) {
          return type == SSH_FILEXFER_TYPE_SYMLINK;
      } else if (permissions != null && (permissions.longValue() & SftpFileAttributes.S_IFLNK) ==
      SftpFileAttributes.S_IFLNK) {
      return true;
    }
    else {
      return false;
    }
  }

  /**
   * Determine whether these attributes refer to a pipe.
   *
   * @return boolean
   */
  public boolean isFifo() {
    if (permissions != null && (permissions.longValue() & SftpFileAttributes.S_IFIFO) ==
      SftpFileAttributes.S_IFIFO) {
      return true;
    }
	return false;
  }

  /**
   * Determine whether these attributes refer to a block special file.
   *
   * @return boolean
   */
  public boolean isBlock() {
    if (permissions != null && (permissions.longValue() & SftpFileAttributes.S_IFBLK) ==
      SftpFileAttributes.S_IFBLK) {
      return true;
    }
	return false;
  }

  /**
   * Determine whether these attributes refer to a character device.
   *
   * @return boolean
   */
  public boolean isCharacter() {
    if (permissions != null && (permissions.longValue() & SftpFileAttributes.S_IFCHR) ==
      SftpFileAttributes.S_IFCHR) {
      return true;
    }
	return false;
  }

  /**
   * Determine whether these attributes refer to a socket.
   *
   * @return boolean
   */
  public boolean isSocket() {
    if (permissions != null && (permissions.longValue() & SftpFileAttributes.S_IFSOCK) ==
      SftpFileAttributes.S_IFSOCK) {
      return true;
    }
	return false;
  }
  
  void setUsername(String username) {
	  this.username = username;
  }
  
  void setGroup(String group) {
	  this.group = group;
  }
}

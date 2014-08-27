package com.sshtools.sftp;

/**
 * Version 4 of the SFTP protocol introduces an ACL field in the
 * {@link SftpFileAttributes} structure.
 *
 * @author Lee David Painter
 */
public class ACL {

    public static final int ACL_ALLOWED_TYPE = 1;
    public static final int ACL_DENIED_TYPE = 1;
    public static final int ACL_AUDIT_TYPE = 1;
    public static final int ACL_ALARM_TYPE = 1;

    int type;
    int flags;
    int mask;
    String who;

    public ACL(int type, int flags, int mask, String who) {
    }

    public int getType() {
        return type;
    }

    public int getFlags() {
        return flags;
    }

    public int getMask() {
        return mask;
    }

    public String getWho() {
        return who;
    }
}

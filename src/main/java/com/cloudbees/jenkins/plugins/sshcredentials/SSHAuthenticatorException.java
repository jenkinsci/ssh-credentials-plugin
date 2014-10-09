package com.cloudbees.jenkins.plugins.sshcredentials;

/**
 * @author stephenc
 * @since 25/10/2012 15:20
 */
public class SSHAuthenticatorException extends RuntimeException {
    public SSHAuthenticatorException() {
        super();
    }

    public SSHAuthenticatorException(Throwable cause) {
        super(cause);
    }

    public SSHAuthenticatorException(String message) {
        super(message);
    }

    public SSHAuthenticatorException(String message, Throwable cause) {
        super(message, cause);
    }
}

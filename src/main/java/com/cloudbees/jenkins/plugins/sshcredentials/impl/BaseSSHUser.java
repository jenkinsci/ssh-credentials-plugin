package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUser;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * @author stephenc
 * @since 28/02/2012 13:44
 */
public class BaseSSHUser extends BaseStandardCredentials implements SSHUser, StandardUsernameCredentials {

    /**
     * Ensure consistent serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The username.
     */
    protected final String username;

    @Nullable
    private Boolean usernameSecret = false;

    public BaseSSHUser(CredentialsScope scope, String id, String username, String description) {
        super(scope, id, description);
        this.username = username;
    }

    protected Object readResolve() {
        if (usernameSecret == null) {
            usernameSecret = true;
        }
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getUsername() {
        return username == null || username.isEmpty() ? System.getProperty("user.name") : username;
    }

    @Override
    public boolean isUsernameSecret() {
        return usernameSecret;
    }

    @DataBoundSetter
    public void setUsernameSecret(boolean usernameSecret) {
        this.usernameSecret = usernameSecret;
    }

}

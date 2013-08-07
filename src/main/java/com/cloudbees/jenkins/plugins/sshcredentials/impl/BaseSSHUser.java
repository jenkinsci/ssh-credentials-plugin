package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUser;
import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.lang.StringUtils;

/**
 * @author stephenc
 * @since 28/02/2012 13:44
 */
public class BaseSSHUser extends BaseCredentials implements SSHUser, StandardUsernameCredentials {

    /**
     * Ensure consistent serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The id.
     */
    protected final String id;
    /**
     * The description.
     */
    protected final String description;
    /**
     * The username.
     */
    protected final String username;

    public BaseSSHUser(CredentialsScope scope, String id, String username, String description) {
        super(scope);
        this.id = IdCredentials.Helpers.fixEmptyId(id);
        this.username = username;
        this.description = description;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getId() {
        return id;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getUsername() {
        return StringUtils.isEmpty(username) ? System.getProperty("user.name") : username;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public String getDescription() {
        return StringUtils.isNotEmpty(description) ? description : "";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        return IdCredentials.Helpers.equals(this, o);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return IdCredentials.Helpers.hashCode(this);
    }
}

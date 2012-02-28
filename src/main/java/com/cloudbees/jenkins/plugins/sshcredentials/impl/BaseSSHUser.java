package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUser;
import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.lang.StringUtils;

import java.util.UUID;

/**
 * @author stephenc
 * @since 28/02/2012 13:44
 */
public class BaseSSHUser extends BaseCredentials implements SSHUser {

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
        this.id = StringUtils.isEmpty(id) ? UUID.randomUUID().toString() : id;
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
}

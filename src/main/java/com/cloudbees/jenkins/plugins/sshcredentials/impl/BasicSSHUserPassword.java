/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPassword;
import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * A simple username / password for use with SSH connections.
 */
public class BasicSSHUserPassword extends BaseCredentials implements SSHUserPassword {

    /**
     * The description.
     */
    private final String description;

    /**
     * The username.
     */
    private final String username;

    /**
     * The password.
     */
    private final Secret password;

    /**
     * Constructor for stapler.
     * @param scope the credentials scope
     * @param username the username.
     * @param password the password.
     * @param description the description.
     */
    @DataBoundConstructor
    public BasicSSHUserPassword(CredentialsScope scope, String username, String password, String description) {
        super(scope);
        this.username = username;
        this.description = description;
        this.password = Secret.fromString(password);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public Secret getPassword() {
        return password;
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
    @Extension
    public static class DescriptorImpl extends CredentialsDescriptor {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.BasicSSHUserPassword_DisplayName();
        }
    }
}

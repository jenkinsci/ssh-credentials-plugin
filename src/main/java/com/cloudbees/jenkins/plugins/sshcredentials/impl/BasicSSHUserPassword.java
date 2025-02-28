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
import com.cloudbees.plugins.credentials.CredentialsResolver;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.ResolveWith;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.Descriptor;
import hudson.util.Secret;

/**
 * A simple username / password for use with SSH connections.
 *
 * @deprecated use {@link UsernamePasswordCredentialsImpl}
 */
@ResolveWith(BasicSSHUserPassword.ResolverImpl.class)
@Deprecated
public class BasicSSHUserPassword extends BaseSSHUser implements SSHUserPassword {

    /**
     * Ensure consistent serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The password.
     */
    private final Secret password;

    /**
     * Constructor for stapler.
     *
     * @param scope       the credentials scope
     * @param id
     * @param username    the username.
     * @param password    the password.
     * @param description the description.
     */
    public BasicSSHUserPassword(CredentialsScope scope, String id, String username, String password,
                                String description) {
        super(scope, id, username, description);
        this.password = Secret.fromString(password);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    public Secret getPassword() {
        return password;
    }

    @Override
    protected Object readResolve() {
        UsernamePasswordCredentialsImpl resolved;
        try {
            resolved = new UsernamePasswordCredentialsImpl(getScope(), getId(), getDescription(), getUsername(), getPassword().getEncryptedValue());
        } catch (Descriptor.FormException e) {
            throw new RuntimeException(e);
        }
        resolved.setUsernameSecret(true);
        return resolved;
    }

    /**
     * Resolve credentials for legacy code.
     *
     * @since 0.5
     */
    public static class ResolverImpl
            extends CredentialsResolver<UsernamePasswordCredentialsImpl, BasicSSHUserPassword> {

        /**
         * Default constructor.
         */
        public ResolverImpl() {
            super(UsernamePasswordCredentialsImpl.class);
        }

        @NonNull
        @Override
        protected BasicSSHUserPassword doResolve(@NonNull UsernamePasswordCredentialsImpl original) {
            return new BasicSSHUserPassword(original.getScope(), original.getId(), original.getUsername(),
                    original.getPassword().getEncryptedValue(), original.getDescription());
        }
    }
}

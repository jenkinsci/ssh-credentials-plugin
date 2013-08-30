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
package com.cloudbees.jenkins.plugins.sshcredentials;

import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.ExtensionPoint;

import java.io.Serializable;

/**
 * Extension point to allow plugging in {@link SSHAuthenticator} implementations for the many SSH client libraries
 * available.
 * <p/>
 * <p/>
 * This object can be shipped to remote to create an {@link SSHAuthenticator} on a remote node.
 *
 * @see SSHAuthenticator#newInstance(Object, SSHUser)
 */
public abstract class SSHAuthenticatorFactory implements ExtensionPoint, Serializable {

    /**
     * Returns an instance of {@link SSHAuthenticator} for the supplied connection and user, or {@code null} if
     * the factory does not support the connection and user combination.
     *
     * @param connection the connection.
     * @param user       the user.
     * @param <C>        the type of connection.
     * @param <U>        the type of user.
     * @return {@code null} if the connection or user is not supported by this factory, or a {@link SSHAuthenticator}
     *         instance bound to the supplied connection and user.
     */
    @Nullable
    protected abstract <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(
            @NonNull C connection,
            @NonNull U user);

    /**
     * Returns an instance of {@link SSHAuthenticator} for the supplied connection and user, or {@code null} if
     * the factory does not support the connection and user combination.
     *
     * @param connection the connection.
     * @param user       the user.
     * @param username   the username or {@code null} to fall back to the username in the user parameter.
     * @param <C>        the type of connection.
     * @param <U>        the type of user.
     * @return {@code null} if the connection or user is not supported by this factory, or a {@link SSHAuthenticator}
     *         instance bound to the supplied connection and user.
     * @since 1.4
     */
    @Nullable
    protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(
            @NonNull C connection,
            @NonNull U user,
            @CheckForNull String username) {
        return newInstance(connection, user);
    }

    /**
     * Returns {@code true} if and only if the supplied connection class and user class are supported by this factory.
     *
     * @param connectionClass the connection class.
     * @param userClass       the user class.
     * @param <C>             the type of connection.
     * @param <U>             the type of user.
     * @return {@code true} if and only if the supplied connection class and user class are supported by this factory.
     */
    protected abstract <C, U extends StandardUsernameCredentials> boolean supports(@NonNull Class<C> connectionClass,
                                                                                   @NonNull Class<U> userClass);

    private static final long serialVersionUID = 1L;
}

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

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.BuildListener;
import hudson.model.Hudson;
import hudson.model.TaskListener;
import hudson.remoting.Callable;
import hudson.remoting.Channel;
import hudson.util.StreamTaskListener;
import jenkins.model.Jenkins;
import net.jcip.annotations.GuardedBy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.anyOf;
import static com.cloudbees.plugins.credentials.CredentialsMatchers.instanceOf;

/**
 * Abstraction for something that can authenticate an SSH connection.
 *
 * @param <C> the type of connection.
 * @param <U> the user to authenticate.
 */
public abstract class SSHAuthenticator<C, U extends StandardUsernameCredentials> {
    /**
     * Our connection.
     */
    @NonNull
    private final C connection;

    /**
     * Our user details.
     */
    @NonNull
    private final U user;

    private final String username;

    /**
     * Lock to prevent threading issues.
     */
    @NonNull
    private final Object lock = new Object();

    /**
     * Authentication state.
     */
    @CheckForNull
    @GuardedBy("lock")
    private Boolean authenticated = null;

    /**
     * Subtypes are expected to report authentication failures to this listener.
     * <p/>
     * For backward compatibility with clients that do not supply a valid listener, use one that's connected
     * to server's stderr. This way, at least we know the error will be reported somewhere.
     */
    @NonNull
    private volatile TaskListener listener = StreamTaskListener.fromStderr();

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     * @param user       the user we will be authenticating as.
     * @deprecated use {@link #SSHAuthenticator(Object, com.cloudbees.plugins.credentials.common.StandardUsernameCredentials, String)}
     */
    @Deprecated
    protected SSHAuthenticator(@NonNull C connection, @NonNull U user) {
        this(connection, user, null);
    }

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     * @param user       the user we will be authenticating as.
     * @param username   the username we will be authenticating as or {@code null} to use the users username.
     * @since 1.4
     */
    protected SSHAuthenticator(@NonNull C connection, @NonNull U user, @CheckForNull String username) {
        connection.getClass(); // throw NPE if null
        user.getClass(); // throw NPE if null
        this.connection = connection;
        this.user = user;
        this.username = username;
    }

    /**
     * Returns the username to authenticate as.
     *
     * @return the username to authenticate as.
     * @since 1.4
     */
    public String getUsername() {
        return username == null ? getUser().getUsername() : username;
    }

    @NonNull
    public TaskListener getListener() {
        return listener;
    }

    /**
     * Sets the {@link TaskListener} that receives errors that happen during the authentication.
     * <p/>
     * If you are doing this as a part of a build, pass in your {@link BuildListener}.
     * Pass in null to suppress the error reporting. Doing so is useful if the caller intends
     * to try another {@link SSHAuthenticator} when this one fails.
     * <p/>
     * For assisting troubleshooting with callers that do not provide a valid listener,
     * by default the errors will be sent to stderr of the server.
     */
    public void setListener(TaskListener listener) {
        if (listener == null) {
            listener = TaskListener.NULL;
        }
        this.listener = listener;
    }

    /**
     * Creates an authenticator that may be able to authenticate the supplied connection with the supplied user.
     *
     * @param connection the connection to authenticate on.
     * @param user       the user to authenticate with.
     * @param <C>        the type of connection.
     * @param <U>        the type of user.
     * @return a {@link SSHAuthenticator} that may or may not be able to successfully authenticate.
     */
    @NonNull
    public static <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user)
            throws InterruptedException, IOException {
        return newInstance(connection, user, null);
    }

    /**
     * Creates an authenticator that may be able to authenticate the supplied connection with the supplied user.
     *
     * @param connection the connection to authenticate on.
     * @param user       the user to authenticate with.
     * @param username   the username or {@code null} to fall back to the username in the user parameter.
     * @param <C>        the type of connection.
     * @param <U>        the type of user.
     * @return a {@link SSHAuthenticator} that may or may not be able to successfully authenticate.
     * @since 1.4
     */
    @NonNull
    public static <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user,
                                                                                                @CheckForNull String
                                                                                                        username)
            throws InterruptedException, IOException {
        connection.getClass(); // throw NPE if null
        user.getClass(); // throw NPE if null
        Collection<SSHAuthenticatorFactory> factories;
        if (Jenkins.getInstance() != null) {
            // if running on the master
            factories = Jenkins.getInstance().getExtensionList(SSHAuthenticatorFactory.class);
        } else {
            // if running on the slave, bring these factories over here
            factories = Channel.current().call(new Callable<Collection<SSHAuthenticatorFactory>, IOException>() {
                private static final long serialVersionUID = 1;
                public Collection<SSHAuthenticatorFactory> call() throws IOException {
                    return new ArrayList<SSHAuthenticatorFactory>(
                            Jenkins.getInstance().getExtensionList(SSHAuthenticatorFactory.class));
                }
            });
        }

        for (SSHAuthenticatorFactory factory : factories) {
            SSHAuthenticator<C, U> result = factory.newInstance(connection, user, username);
            if (result != null && result.canAuthenticate()) {
                return result;
            }
        }
        return new SSHAuthenticator<C, U>(connection, user, username) {
            @Override
            protected boolean doAuthenticate() {
                return false;
            }
        };
    }

    /**
     * @deprecated Use {@link #newInstance(Object, StandardUsernameCredentials)} instead.
     */
    @Deprecated
    public static SSHAuthenticator<Object, StandardUsernameCredentials> newInstance(Object connection, SSHUser user)
            throws InterruptedException, IOException {
        return newInstance(connection, (StandardUsernameCredentials) user, null);
    }

    /**
     * Returns {@code true} if and only if the supplied connection class and user class are supported by at least one
     * factory.
     *
     * @param connectionClass the connection class.
     * @param userClass       the user class.
     * @param <C>             the type of connection.
     * @param <U>             the type of user.
     * @return {@code true} if and only if the supplied connection class and user class are supported by at least one
     *         factory.
     */
    public static <C, U extends StandardUsernameCredentials> boolean isSupported(@NonNull Class<C> connectionClass,
                                                                                 @NonNull Class<U> userClass) {
        connectionClass.getClass(); // throw NPE if null
        userClass.getClass(); // throw NPE if null
        for (SSHAuthenticatorFactory factory : Hudson.getInstance().getExtensionList(SSHAuthenticatorFactory.class)) {
            if (factory.supports(connectionClass, userClass)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Filters {@link Credentials} returning only those which are supported with the specified type of connection.
     *
     * @param credentials     the credentials to filter.
     * @param connectionClass the type of connection to filter for.
     * @return a list of {@link SSHUser} credentials appropriate for use with the supplied type of connection.
     * @deprecated Use
     *             {@link CredentialsMatchers#filter(List, CredentialsMatcher)}
     *             and {@link #matcher(Class)}
     */
    public static List<? extends StandardUsernameCredentials> filter(Iterable<? extends Credentials> credentials,
                                                                     Class<?> connectionClass) {
        List<StandardUsernameCredentials> result = new ArrayList<StandardUsernameCredentials>();
        CredentialsMatcher matcher = matcher(connectionClass);
        for (Credentials credential : credentials) {
            if (credential instanceof StandardUsernameCredentials && matcher.matches(credential)) {
                result.add((StandardUsernameCredentials) credential);
            }
        }
        return result;
    }


    /**
     * Returns a {@link CredentialsMatcher} that matches the generic types of credential that are valid for use over
     * SSH.
     * When you know the connection type you will be using, it is better to use {@link #matcher(Class)}.
     *
     * @return a {@link CredentialsMatcher} that matches the generic types of credential that are valid for use over
     *         SSH.
     */
    public static CredentialsMatcher matcher() {
        return anyOf(
                instanceOf(StandardUsernamePasswordCredentials.class),
                instanceOf(SSHUserPrivateKey.class)
        );
    }

    /**
     * Creates a {@link CredentialsMatcher} for the specific type of connection.
     *
     * @param connectionClass the type of connection.
     * @return a {@link CredentialsMatcher}
     * @since 0.5
     */
    public static CredentialsMatcher matcher(Class<?> connectionClass) {
        return new Matcher(connectionClass);
    }

    /**
     * {@link CredentialsMatcher} that matches credentials supported by a specific connection class.
     *
     * @since 0.5
     */
    private static class Matcher implements CredentialsMatcher {

        /**
         * The connection class.
         */
        private final Class<?> connectionClass;

        /**
         * Constructor.
         *
         * @param connectionClass the connection class.
         */
        public Matcher(Class<?> connectionClass) {
            this.connectionClass = connectionClass;
        }

        /**
         * {@inheritDoc}
         */
        public boolean matches(@NonNull Credentials item) {
            return item instanceof StandardUsernameCredentials && isSupported(connectionClass,
                    (StandardUsernameCredentials.class.cast(item)).getClass());
        }
    }

    /**
     * Returns {@code true} if the bound connection is in a state where authentication can be tried using the
     * supplied credentials.
     * <p/>
     * Subclasses can override this if they can tell whether it is possible to make an authentication attempt, default
     * implementation is one-shot always.
     *
     * @return {@code true} if the bound connection is in a state where authentication can be tried using the
     *         supplied credentials.
     */
    public boolean canAuthenticate() {
        synchronized (lock) {
            return authenticated == null;
        }
    }

    /**
     * Returns {@code true} if the bound connection has been authenticated.
     *
     * @return {@code true} if the bound connection has been authenticated.
     */
    public final boolean isAuthenticated() {
        synchronized (lock) {
            return authenticated != null && authenticated;
        }
    }

    /**
     * Gets the bound connection.
     *
     * @return the bound connection.
     */
    @NonNull
    protected final C getConnection() {
        return connection;
    }

    /**
     * Gets the supplied credentials.
     *
     * @return the supplied credentials.
     */
    @NonNull
    public U getUser() {
        return user;
    }

    /**
     * SPI for authenticating the bound connection using the supplied credentials.
     * <p/>
     * As a guideline, authentication errors should be reported to {@link #getListener()}
     * before this method returns with {@code false}. This helps an user better understand
     * what is tried and failing. Logging can be used in addition to this to capture further details.
     * (in contrast, please avoid reporting a success to the listener to improve S/N ratio)
     *
     * @return {@code true} if and only if authentication was successful.
     */
    protected abstract boolean doAuthenticate();

    /**
     * Returns the mode of authentication that this {@link SSHAuthenticator} supports.
     *
     * @return the mode of authentication that this {@link SSHAuthenticator} supports.
     * @since 0.2
     */
    @NonNull
    public Mode getAuthenticationMode() {
        return Mode.AFTER_CONNECT;
    }

    /**
     * @deprecated as of 0.3
     *             Use {@link #authenticate(TaskListener)} and provide a listener to receive errors.
     */
    public final boolean authenticate() {
        synchronized (lock) {
            if (canAuthenticate()) {
                try {
                    authenticated = doAuthenticate();
                } catch (Throwable t) {
                    Logger.getLogger(getClass().getName())
                            .log(Level.WARNING, "Uncaught exception escaped doAuthenticate method", t);
                    authenticated = false;
                }
            }
            return isAuthenticated() || Mode.BEFORE_CONNECT.equals(getAuthenticationMode());
        }
    }

    /**
     * Authenticate the bound connection using the supplied credentials.
     *
     * @return For an {@link #getAuthenticationMode()} of {@link Mode#BEFORE_CONNECT} the return value is
     *         always {@code true} otherwise the return value is {@code true} if and only if authentication was
     *         successful.
     */
    public final boolean authenticate(TaskListener listener) {
        setListener(listener);
        return authenticate();
    }

    /**
     * Same as {@link SSHUserPrivateKey#getPrivateKeys} but backward compatible for old implementations.
     *
     * @since 1.3
     */
    @SuppressWarnings("deprecation")
    public static List<String> getPrivateKeys(SSHUserPrivateKey user) {
        try {
            return user.getPrivateKeys();
        } catch (AbstractMethodError x) {
            return Collections.singletonList(user.getPrivateKey());
        }
    }

    /**
     * Reflects the different styles of applying authentication.
     *
     * @since 0.2
     */
    public static enum Mode {
        /**
         * This {@link SSHAuthenticator} performs authentication before establishing the connection.
         */
        BEFORE_CONNECT,
        /**
         * This {@link SSHAuthenticator} performs authentication after establishing the connection.
         */
        AFTER_CONNECT;
    }
}

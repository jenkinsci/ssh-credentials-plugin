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
import hudson.ExtensionList;
import hudson.Functions;
import hudson.model.BuildListener;
import hudson.model.TaskListener;
import hudson.remoting.Channel;
import hudson.util.StreamTaskListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import jenkins.model.Jenkins;
import jenkins.security.SlaveToMasterCallable;
import net.jcip.annotations.GuardedBy;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.anyOf;
import static com.cloudbees.plugins.credentials.CredentialsMatchers.instanceOf;
import jenkins.util.JenkinsJVM;

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
     * <p>
     * For backward compatibility with clients that do not supply a valid listener, use one that's connected
     * to server's stderr. This way, at least we know the error will be reported somewhere.
     * </p>
     */
    @NonNull
    private volatile TaskListener listener = StreamTaskListener.fromStderr();

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     * @param user       the user we will be authenticating as.
     * @deprecated use
     * {@link #SSHAuthenticator(Object, com.cloudbees.plugins.credentials.common.StandardUsernameCredentials, String)}
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
        this.connection = Objects.requireNonNull(connection);
        this.user = Objects.requireNonNull(user);
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
     * <p>
     * If you are doing this as a part of a build, pass in your {@link BuildListener}.
     * Pass in null to suppress the error reporting. Doing so is useful if the caller intends
     * to try another {@link SSHAuthenticator} when this one fails.
     * </p><p>
     * For assisting troubleshooting with callers that do not provide a valid listener,
     * by default the errors will be sent to stderr of the server.
     * </p>
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
        Objects.requireNonNull(connection);
        Objects.requireNonNull(user);
        Collection<SSHAuthenticatorFactory> factories;
        try {
            factories = lookupFactories();
        } catch (LinkageError e) {
            // we are probably running on a remote agent and controller only classes are banned from remote class loading
            factories = null;
        } catch (IllegalStateException e) {
            // Jenkins.getInstance() is throwing an IllegalStateException when invoked on a remote agent
            factories = null;
        }
        if (factories == null) {
            // we are probably running on a remote agent
            Channel channel = Channel.current();
            if (channel == null) {
                // ok we are not running on a remote agent, we have no ability to authenticate
                factories = Collections.emptySet();
            } else {
                // call back to the controller and get an instance
                factories = channel.call(new NewInstance());
            }

        }

        return factories.stream()
                .map(factory -> factory.newInstance(connection, user, username))
                .filter(Objects::nonNull)
                .filter(SSHAuthenticator::canAuthenticate)
                .findFirst()
                .orElseGet(() -> new SSHNonauthenticator<>(connection, user, username));
    }

    /**
     * This method allows a build agent to invoke {@link #newInstance(Object, StandardUsernameCredentials, String)}
     * after we start blocking build agents from loading master-only classes such as {@link Jenkins} and
     * {@link ExtensionList} as the JVM will not attempt to load these classes until this method gets invoked.
     *
     * @return the {@link SSHAuthenticatorFactory} instances (or {@code null} if you invoke from a build agent)
     * @throws LinkageError          if you invoke from a build agent
     * @throws IllegalStateException if you invoke from a build agent
     */
    private static List<SSHAuthenticatorFactory> lookupFactories() {
        return JenkinsJVM.isJenkinsJVM() ? ExtensionList.lookup(SSHAuthenticatorFactory.class) : null;
    }

    /**
     * @deprecated Use {@link #newInstance(Object, StandardUsernameCredentials)} instead.
     */
    @Deprecated
    public static SSHAuthenticator<Object, StandardUsernameCredentials> newInstance(Object connection, SSHUser user)
            throws InterruptedException, IOException {
        return newInstance(connection, user, null);
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
     * factory.
     */
    public static <C, U extends StandardUsernameCredentials> boolean isSupported(@NonNull Class<C> connectionClass,
                                                                                 @NonNull Class<U> userClass) {
        Objects.requireNonNull(connectionClass);
        Objects.requireNonNull(userClass);
        return ExtensionList.lookup(SSHAuthenticatorFactory.class).stream()
                .anyMatch(factory -> factory.supports(connectionClass, userClass));
    }

    /**
     * Filters {@link Credentials} returning only those which are supported with the specified type of connection.
     *
     * @param credentials     the credentials to filter.
     * @param connectionClass the type of connection to filter for.
     * @return a list of {@link SSHUser} credentials appropriate for use with the supplied type of connection.
     * @deprecated Use
     * {@link CredentialsMatchers#filter(List, CredentialsMatcher)}
     * and {@link #matcher(Class)}
     */
    public static List<? extends StandardUsernameCredentials> filter(Iterable<? extends Credentials> credentials,
                                                                     Class<?> connectionClass) {
        CredentialsMatcher matcher = matcher(connectionClass);
        return StreamSupport.stream(credentials.spliterator(), false)
                .filter(StandardUsernameCredentials.class::isInstance)
                .filter(matcher::matches)
                .map(StandardUsernameCredentials.class::cast)
                .collect(Collectors.toList());
    }


    /**
     * Returns a {@link CredentialsMatcher} that matches the generic types of credential that are valid for use over
     * SSH.
     * When you know the connection type you will be using, it is better to use {@link #matcher(Class)}.
     *
     * @return a {@link CredentialsMatcher} that matches the generic types of credential that are valid for use over
     * SSH.
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
         * Standardize serialization across different JVMs.
         *
         * @since 1.13
         */
        // historical value generated from 1.12 code with Java 8
	private static final Long serialVersionUID = -5078593817273453864L; 

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
                    ((StandardUsernameCredentials) item).getClass());
        }
    }

    /**
     * Returns {@code true} if the bound connection is in a state where authentication can be tried using the
     * supplied credentials.
     * <p>
     * Subclasses can override this if they can tell whether it is possible to make an authentication attempt, default
     * implementation is one-shot always.
     * </p>
     *
     * @return {@code true} if the bound connection is in a state where authentication can be tried using the
     * supplied credentials.
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
     * <p>
     * As a guideline, authentication errors should be reported to {@link #getListener()}
     * before this method returns with {@code false}. This helps an user better understand
     * what is tried and failing. Logging can be used in addition to this to capture further details.
     * (in contrast, please avoid reporting a success to the listener to improve S/N ratio)
     * </p>
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
     * Use {@link #authenticate(TaskListener)} and provide a listener to receive errors.
     */
    public final boolean authenticate() {
        synchronized (lock) {
            if (canAuthenticate()) {
                try {
                    authenticated = doAuthenticate();
                } catch (Throwable t) {
                    Functions.printStackTrace(t, listener.error("SSH authentication failed"));
                    authenticated = false;
                }
            }
            return isAuthenticated() || Mode.BEFORE_CONNECT.equals(getAuthenticationMode());
        }
    }

    /**
     * @since TODO
     * @throws IOException Failure reason
     */
    public final void authenticateOrFail() throws IOException {
        synchronized (lock) {
            if (!canAuthenticate()) {
                throw new IOException("Cannot authenticate");
            }

            try {
                authenticated = doAuthenticate();
            } catch (Throwable t) {
                throw  new IOException("SSH authentication failed", t);
            }
        }
    }

    /**
     * Authenticate the bound connection using the supplied credentials.
     *
     * @return For an {@link #getAuthenticationMode()} of {@link Mode#BEFORE_CONNECT} the return value is
     * always {@code true} otherwise the return value is {@code true} if and only if authentication was
     * successful.
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
    public enum Mode {
        /**
         * This {@link SSHAuthenticator} performs authentication before establishing the connection.
         */
        BEFORE_CONNECT,
        /**
         * This {@link SSHAuthenticator} performs authentication after establishing the connection.
         */
        AFTER_CONNECT
    }

    /**
     * A callable invoked from the remote agents to retrieve the {@link SSHAuthenticatorFactory} instances.
     */
    private static class NewInstance extends SlaveToMasterCallable<Collection<SSHAuthenticatorFactory>, IOException> {
        /**
         * Standardize serialization.
         */
        private static final long serialVersionUID = 1L;

        /**
         * {@inheritDoc}
         */
        public Collection<SSHAuthenticatorFactory> call() throws IOException {
            return new ArrayList<>(ExtensionList.lookup(SSHAuthenticatorFactory.class));
        }
    }

    /**
     * A dummy {@link SSHAuthenticator} that will never authenticate.
     *
     * @param <C> the connection type.
     * @param <U> the credential type.
     */
    private static class SSHNonauthenticator<C, U extends StandardUsernameCredentials> extends SSHAuthenticator<C, U> {
        /**
         * {@inheritDoc}
         */
        public SSHNonauthenticator(C connection, U user, String username) {
            super(connection, user, username);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected boolean doAuthenticate() {
            return false;
        }
    }
}

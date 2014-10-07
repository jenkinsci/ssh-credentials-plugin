package com.cloudbees.jenkins.plugins.sshcredentials;

import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.AbstractIdCredentialsListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.security.ACL;
import jenkins.model.Jenkins;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/** @deprecated Use {@link StandardUsernameListBoxModel} with {@link SSHAuthenticator} instead. */
public class SSHUserListBoxModel extends AbstractIdCredentialsListBoxModel<SSHUserListBoxModel,StandardUsernameCredentials> {
    /**
     * {@inheritDoc}
     */
    @NonNull
    protected String describe(@NonNull StandardUsernameCredentials c) {
        String description = Util.fixEmptyAndTrim(c.getDescription());
        return c.getUsername() + (description != null ? " (" + description + ")" : "");
    }

    /**
     * @deprecated use {@link #with(com.cloudbees.plugins.credentials.common.IdCredentials)}
     */
    @Deprecated
    public SSHUserListBoxModel add(StandardUsernameCredentials u) {
        with(u);
        return this;
    }

    /**
     * Adds a collection of credentials (they will be filtered with {@link SSHAuthenticator#matcher()} implicitly).
     *
     * @param col the collection of credentials.
     * @return {@code this} for method chaining.
     * @deprecated use {@link #withMatching(CredentialsMatcher, Iterable)} or {@link #withAll(Iterable)}
     */
    @Deprecated
    public SSHUserListBoxModel addCollection(Collection<? extends StandardUsernameCredentials> col) {
        withMatching(SSHAuthenticator.matcher(), col);
        return this;
    }

    /**
     * Adds all the system-scoped credentials (they will be filtered with {@link SSHAuthenticator#matcher()}
     * implicitly).
     * <p/>
     * These credentials are meant to be used for system configuration and other things scoped to the {@link Jenkins}
     * object,
     * such as slaves.
     *
     * @return {@code this} for method chaining.
     * @deprecated use {@link #withSystemScopeCredentials()}
     */
    @Deprecated
    public SSHUserListBoxModel addSystemScopeCredentials() {
        return withSystemScopeCredentials();
    }

    /**
     * Adds all the system-scoped credentials (they will be filtered with {@link SSHAuthenticator#matcher()}
     * implicitly).
     * <p/>
     * These credentials are meant to be used for system configuration and other things scoped to the {@link Jenkins}
     * object,
     * such as slaves.
     *
     * @return {@code this} for method chaining.
     */
    public SSHUserListBoxModel withSystemScopeCredentials() {
        return withSystemScopeCredentials(Collections.<DomainRequirement>emptyList());
    }

    /**
     * Adds all the system-scoped credentials (they will be filtered with {@link SSHAuthenticator#matcher()}
     * implicitly).
     * <p/>
     * These credentials are meant to be used for system configuration and other things scoped to the {@link Jenkins}
     * object,
     * such as slaves.
     *
     * @param domainRequirements the domain requirements
     * @return {@code this} for method chaining.
     */
    public SSHUserListBoxModel withSystemScopeCredentials(DomainRequirement... domainRequirements) {
        return withSystemScopeCredentials(SSHAuthenticator.matcher(), domainRequirements);
    }

    /**
     * Adds all the system-scoped credentials.
     * <p/>
     * These credentials are meant to be used for system configuration and other things scoped to the {@link Jenkins}
     * object,
     * such as slaves.
     *
     * @param matcher            a matcher to filter the credentials
     * @param domainRequirements the domain requirements
     * @return {@code this} for method chaining.
     */
    public SSHUserListBoxModel withSystemScopeCredentials(CredentialsMatcher matcher,
                                                          DomainRequirement... domainRequirements) {
        return withSystemScopeCredentials(matcher, Arrays.asList(domainRequirements));
    }

    /**
     * Adds all the system-scoped credentials (they will be filtered with {@link SSHAuthenticator#matcher()}
     * implicitly).
     * <p/>
     * These credentials are meant to be used for system configuration and other things scoped to the {@link Jenkins}
     * object,
     * such as slaves.
     *
     * @param domainRequirements the domain requirements
     * @return {@code this} for method chaining.
     */
    public SSHUserListBoxModel withSystemScopeCredentials(List<DomainRequirement> domainRequirements) {
        return withSystemScopeCredentials(SSHAuthenticator.matcher(), domainRequirements);
    }

    /**
     * Adds all the system-scoped credentials.
     * <p/>
     * These credentials are meant to be used for system configuration and other things scoped to the {@link Jenkins}
     * object,
     * such as slaves.
     *
     * @param matcher            a matcher to filter the credentials
     * @param domainRequirements the domain requirements
     * @return {@code this} for method chaining.
     */
    public SSHUserListBoxModel withSystemScopeCredentials(CredentialsMatcher matcher,
                                                          List<DomainRequirement> domainRequirements) {
        withMatching(matcher,
                CredentialsProvider.lookupCredentials(StandardUsernameCredentials.class, Jenkins.getInstance(),
                        ACL.SYSTEM, domainRequirements));
        return this;
    }

}

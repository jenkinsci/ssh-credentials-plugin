package com.cloudbees.jenkins.plugins.sshcredentials;

import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.AbstractIdCredentialsListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.model.Job;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static com.cloudbees.plugins.credentials.CredentialsMatchers.filter;

/**
 * {@link ListBoxModel} with {@link StandardUsernameCredentials} support.
 * <p/>
 * This class is convenient for providing the config.groovy/.jelly fragment for a collection of {@link StandardUsernameCredentials} objects.
 * <p/>
 * If you want to let the user configure an {@link StandardUsernameCredentials} object, do the following:
 * <p/>
 * First, create a field that stores the credential ID and defines a corresponding parameter in the constructor:
 * <p/>
 * <pre>
 * private String credentialId;
 *
 * &#64;DataBoundConstructor
 * public MyModel( .... , String credentialId) {
 *     this.credentialId = credentialId;
 *     ...
 * }
 * </pre>
 * <p/>
 * Your <tt>config.groovy</tt> should have the following entry to render a drop-down list box:
 * <p/>
 * <pre>
 * f.entry(title:_("Credentials"), field:"credentialId") {
 *     f.select()
 * }
 * </pre>
 * <p/>
 * Finally, your {@link Descriptor} implementation should have the <tt>doFillCredentialsIdItems</tt> method, which
 * lists up the credentials available in this context:
 * <p/>
 * <pre>
 * public SSHUserListBoxModel doFillCredentialsIdItems() {
 *     return new SSHUserListBoxModel()
 *             .addCollection(CredentialsProvider.lookupCredentials(SSHUser.class,...));
 * }
 * </pre>
 * <p/>
 * <p/>
 * Exactly which overloaded version of the {@link CredentialsProvider#lookupCredentials(Class)} depends on
 * the context in which your model operates. Here are a few common examples:
 * <p/>
 * <dl>
 * <dt>System-level settings
 * <dd>
 * If your model is a singleton in the whole Jenkins instance, things that belong to the root {@link Jenkins}
 * (such as slaves), or do not have any ancestors serving as the context, then use {@link #addSystemScopeCredentials()}.
 * <p/>
 * <dt>Job-level settings
 * <dd>
 * If your model is a configuration fragment added to a {@link Item} (such as its major subtype {@link Job}),
 * then use that {@link Item} as the context and call {@link CredentialsProvider#lookupCredentials(Class, Item)}
 * See below:
 * <p/>
 * <pre>
 * public SSHUserListBoxModel doFillCredentialsIdItems(@AncestorInPath AbstractProject context) {
 *     return new SSHUserListBoxModel().addCollection(
 *         CredentialsProvider.lookupCredentials(StandardUsernameCredentials.class, context, auth, domainRequirements)));
 * }
 * </pre>
 * </dl>
 *
 * @author Kohsuke Kawaguchi
 */
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

package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.cli.ListCredentialsAsXmlCommand;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainSpecification;
import com.cloudbees.plugins.credentials.domains.HostnameSpecification;
import hudson.cli.CLICommandInvoker;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.Collections;

import static hudson.cli.CLICommandInvoker.Matcher.succeeded;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class CLICommandsTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();
    private CredentialsStore store = null;

    @Before
    public void clearCredentials() {
        SystemCredentialsProvider.getInstance().setDomainCredentialsMap(
                Collections.singletonMap(Domain.global(), Collections.<Credentials>emptyList()));
        for (CredentialsStore s : CredentialsProvider.lookupStores(Jenkins.getInstance())) {
            if (s.getProvider() instanceof SystemCredentialsProvider.ProviderImpl) {
                store = s;
                break;
            }
        }
        assertThat("The system credentials provider is enabled", store, notNullValue());
    }

    @Test
    public void listCredentialsAsXML() throws IOException {
        Domain smokes = new Domain("smokes", "smoke test domain",
                Collections.<DomainSpecification>singletonList(new HostnameSpecification("smokes.example.com", null)));
        BasicSSHUserPrivateKey credentials1 = new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "smokes-id-1", "john.doe",
                new BasicSSHUserPrivateKey.FileOnMasterPrivateKeySource("/tmp/test"),
                "passphrase",
                "Smokes CLI Command Test");
        BasicSSHUserPrivateKey credentials2 = new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "smokes-id-2", "john.doe",
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource("test"),
                "passphrase",
                "Smokes CLI Command Test");
        BasicSSHUserPrivateKey credentials3 = new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL, "smokes-id-3", "john.doe",
                new BasicSSHUserPrivateKey.UsersPrivateKeySource(),
                "passphrase",
                "Smokes CLI Command Test");
        CLICommandInvoker invoker = new CLICommandInvoker(r, new ListCredentialsAsXmlCommand());
        CLICommandInvoker.Result result = invoker.invokeWithArgs("system::system::jenkins");
        assertThat(result, succeeded());
        assertThat(result.stdout(), not(containsString("<id>smokes-id</id>")));

        store.addDomain(smokes, credentials1);
        store.addDomain(smokes, credentials2);
        store.addDomain(smokes, credentials3);

        invoker = new CLICommandInvoker(r, new ListCredentialsAsXmlCommand());
        result = invoker.invokeWithArgs("system::system::jenkins");
        System.out.println(result.stdout());
        assertThat(result, succeeded());
        assertThat(result.stdout(), allOf(
                containsString("<id>smokes-id-1</id>"),
                containsString("<id>smokes-id-2</id>"),
                containsString("<id>smokes-id-3</id>"),
                containsString("<name>smokes</name>"),
                containsString("<com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey>"),
                containsString("<privateKeySource class=\"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$FileOnMasterPrivateKeySource\">"),
                containsString("<privateKeySource class=\"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$DirectEntryPrivateKeySource\">"),
                containsString("<privateKeySource class=\"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey$UsersPrivateKeySource\"/>")
        ));
    }
}

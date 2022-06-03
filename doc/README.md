# SSH Credentials Plugin

This plugin allows you to store SSH credentials in Jenkins. For more information on how to create and use credentials in general in Jenkins, please visit the [Credentials Plugin description page](https://plugins.jenkins.io/credentials).  

## For Developers

### Using with Apache Mina SSHD client library

Get the authenticator after you have opened the [ClientSession](https://javadoc.io/static/org.apache.sshd/sshd-core/2.8.0/org/apache/sshd/client/session/ClientSession.html) and let it handle authentication for you:

```java
StandardUsernameCredentials user = ...
SshClient client = SshClient.setUpDefaultClient();
client.start();

try (ClientSession session = client.connect(user, host, port)
    .verify(...timeout...)
    .getSession()) {
  
  SSHAuthenticator authenticator = SSHAuthenticator.newInstance(connection, user);
  if (!authenticator.authenticate()) throw new RuntimeException("Couldn't authenticate");
  
  ...
}
```

### Using with Trilead SSH client library

Get the authenticator after you have opened the connection and let it handle authentication for you:

```
StandardUsernameCredentials user = ...
Connection connection = ...

SSHAuthenticator authenticator = SSHAuthenticator.newInstance(connection, user);
if (!authenticator.authenticate()) throw new RuntimeException("Couldn't authenticate");
```

### Using with JSch SSH client library

Get the authenticator before you have opened the connection (using the `JSchConnector`, 
needed because of the strange dichotomy with JSch between public key authentication 
and user/password authentication) and let feed in authentication for you:

```
StandardUsernameCredentials user = ...
JSchConnector connector = new JSchConnector(user.getUsername(), hostName, port);

SSHAuthenticator authenticator = SSHAuthenticator.newInstance(connector, user);
authenticator.authenticate(); 
Session session = connector.getSession(); 
session.setConfig(...); 
session.connect(timeout);
```

## Version history

Please refer to the [changelog](/CHANGELOG.md)

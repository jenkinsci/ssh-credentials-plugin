//TODO: this snippet, as well as ids in passphrase and private key fields can be removed once https://issues.jenkins.io/browse/JENKINS-65616 is completed
const passphraseElements = document.getElementsByClassName('sshCredentials_passphrase');

if (passphraseElements.length > 0) {
// Failsafe in case there's more than 1 element we'll only use the first one. Should not happen.
    passphraseElements[0].addEventListener("change", event => {
        var newEvent = new Event("change", {"bubbles": true})
        const privateKeyElements = document.getElementsByName('_.privateKey');
        if (privateKeyElements.length > 0) {
            privateKeyElements[0].dispatchEvent(newEvent)
        }
    })
}
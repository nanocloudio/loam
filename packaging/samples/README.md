# Sample credentials — NOT credentials

`ca.pem`, `node.der` and `node.key.der` exist only so `fluxor publish` and
`fluxor ci` can check that each mutual-TLS service under `../service/` builds
with its documented examples (its graph's `type: file` params name a sample
here). They are throwaway keys, published to everyone with this repository,
and trusted by nothing: a deployment passes its own node certificate, key and
client CA as the bundle's `ca`, `cert` and `key` params at run time, and the
published bundles carry none of these files.

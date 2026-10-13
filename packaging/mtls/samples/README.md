# Sample credentials — NOT credentials

`ca.pem`, `node.der` and `node.key.der` exist only so `fluxor publish bundle`
can check that each service template here builds with its documented
examples (`type = "file"` params name a sample beside the manifest). They are
throwaway keys, published to everyone with this repository, and trusted by
nothing: a deployment passes its own node certificate, key and client CA as
the bundle's `ca`, `cert` and `key` params at run time, and the published
bundles carry none of these files.

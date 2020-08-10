# Datashards

**Experimental**

A golang implementation of a Datashards proposal.

This library only supports serialization of data to and from Datashards, which
are encrypted OCAP payloads that are content-addressible. There are two main
Datashards forms: IDSC (Immutable) and MDSC (Mutable).

Not implemented are any transports for actually fetching the requisite data,
nor how to manage key data. They could come from a local file system or a
network.

This library is more utilitarian of serialization and deserialization. It could
allow building higher-level datashards clients that actually do data fetching,
key management, and appropriately utilizing the object capabilities for
transformations and writes.

This library is not ready for production use and the API is not stable.

## Content Addressing

### idsc

Handling an IDSC is pretty straightforward: if it was given then not only can
it be located but it also contains the symmetric key that can be used to
decrypt the information.

```go
idsc, err := dshards.ParseIDSC("idsc:0p.X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo.eekxqfiZIcEnc8cpR-sD_3X3qLaTzQW-KnovArMkGP0")
urn, err := idsc.URN()

// urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo
fmt.Println(urn)
```

Note that the URN only allows for people to locate the content, not decrypt it.

### mdsc

MDSC is slightly more complex. Once parsed, the caller is given a `Cap`
interface, which can be type-casted to a `VerifyCap`, a `ReadCap`, or a
`ReadWriteCap` depending on the caller's expected needs. The casting will fail
when you try to cast to an improper permission level, for example parsing a
verify-only capability and converting it to a `ReadCap`.

An MDSC is always at least a `VerifyCap`. A `ReadCap` is also a `VerifyCap`. And
a `ReadWriteCap` is also a `ReadCap`.

Note that MDSC relies on key data being stored and available

```go
mdsc, err := dshards.ParseMDSC("mdsc:v.0p.gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk.6B4Vy69Z6GnqF3VAk8eZkUBZbXgR5tWWoC1C_6Pbe7g")
if _, ok := mdsc.(dshards.VerifyCap); ok {
  // Will print
  fmt.Println("verify-cap")
}
if _, ok := mdsc.(dshards.ReadCap); ok {
  // Will NOT print
  fmt.Println("read-cap")
}
if _, ok := mdsc.(dshards.ReadWriteCap); ok {
  // Will NOT print
  fmt.Println("read-write-cap")
}
urn, err := mdsc.KeyDataURN()

// urn:sha256d:gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk
fmt.Println(urn)
```

If you're given a more permissive capability, you can always turn it into a more
restrictive one:

```go
var rwcap dshards.ReadWriteCap = //...
var ronly dshards.ReadCap = rwcap.ReadCap()
var vonly dshards.VerifyCap = ronly.VerifyCap() // or rwcap.VerifyCap()
```

## Encrypting And Decrypting

The core function of Datashards is its ability to encode any byte stream into a
series of encrypted chunks of data that are protected by the aforementioned
capabilities.

### Encryption

```go
plaintext := []byte("Hello, earth!")
symmetricKey := //... 
rootIndex, privShardsSlice, err := dshards.Encrypt(plaintext, symmetricKey, dshards.PROTO_ZERO_SUITE)

// This will be the "root" datashard, which is private.
var rootShard dshards.PrivateShard = privShardsSlice[rootIndex]
// The public version we can share, as others that have its URN can locate the
// content without having access to the encryption keys.
shareableShard, err := rootShard.PublicShard()

// For sharing without giving access to encrypted contents.
// urn:sha256d:...etc...
fmt.Println(shareableShard.Address)
// Prints ciphertext, no key
fmt.Println(shareableShard.Content)

// For sharing with giving access to encrypted contents.
// idsc:...etc...
fmt.Println(rootShard.AddressAndKey)
// Still prints ciphertext, but the symmetric key is in the IDSC above
fmt.Println(rootShard.Content)
```

### IDSC Decryption

This is the rough API design as it currently is. It's very rough around the
edges and requires small changes to actually support code like this:

```go
var rootShard dshards.PrivateShard = //...
var suite dshards.Suite = //... from idsc
r, err := dshards.Decrypt(rootShard, suite)
var toFetch []dshards.URN = r.ToFetch()
for len(toFetch) > 0 {
  var shards []dshards.PrivateShard
  for _, urn := range toFetch {
    // Left for reader: Fetch the shard at the URN
    shards = append(shards, /* ... */)
  }
  r, err = dshards.DecryptFetchedResult(r, shards, suite)
}
plaintext := r.Content()
```

### MDSC Decryption & History

MDSC has additional concerns for being mutable. It has a concept of history,
which is bound to change to be a merkle-tree or something similar, and supports
the additional read/write distinction that IDSC does not have (it either both
reads & writes, or doesn't permit either).

The `History`, `HistoryReadOnly`, and `HistoryVerifyOnly` must be a part of the
fetching process to properly support datashards. These histories are expected to
be payloads of other datashards, and are currently serialized as `syrup` (but
could be serialized as `sexp`).

## Further Work

* This library needs a suitable abstraction for the fetching part in order to
  support multiple potential use cases, from on-disk local encryption to
  networked data distribution.
* This library's API design needs to be iterated upon to hide more
  implementation details.
* Most serialization primitives are missing suitable accessors, which may not
  be needed if the API is iterated upon.

## Thanks

Thanks to Serge and Chris for their prototypical implementations in Racket and
Python. This does not interoperate with those, simply because this library does
not support any kind of data fetching (whether in-memory, on-disk, or
networked).

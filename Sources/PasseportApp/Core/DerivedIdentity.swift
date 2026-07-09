import Foundation

struct DerivedIdentity: Decodable, Equatable {
    let ssh: SSHIdentity
    let pgp: PGPIdentity
    let age: AgeIdentity
    let minisign: MinisignIdentity
}

struct MinisignIdentity: Decodable, Equatable {
    /// The full minisign public-key file contents (comment line + base64).
    let publicKey: String
    /// Hex of the 8-byte minisign key id.
    let keyID: String

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case keyID = "key_id"
    }
}

struct SSHIdentity: Decodable, Equatable {
    let publicKey: String

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
    }
}

struct AgeIdentity: Decodable, Equatable {
    let recipient: String
}

struct PGPIdentity: Decodable, Equatable {
    let fingerprint: String
    let publicKey: String
    let secretKey: String

    enum CodingKeys: String, CodingKey {
        case fingerprint
        case publicKey = "public_key"
        case secretKey = "secret_key"
    }
}

extension DerivedIdentity {
    var publicBundle: String {
        """
        # Passeport public keys

        ## SSH (OpenPGP authentication subkey)
        \(ssh.publicKey)

        ## OpenPGP fingerprint
        \(pgp.fingerprint)

        ## OpenPGP public key
        \(pgp.publicKey)

        ## age recipient (OpenPGP encryption subkey)
        \(age.recipient)

        ## minisign public key (seed-derived Ed25519)
        \(minisign.publicKey)
        """
    }

    var privateBundle: String {
        """
        # Passeport private keys

        ## OpenPGP secret key
        \(pgp.secretKey)
        """
    }
}

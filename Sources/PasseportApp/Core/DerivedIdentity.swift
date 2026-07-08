import Foundation

struct DerivedIdentity: Decodable, Equatable {
    let ssh: SSHIdentity
    let pgp: PGPIdentity
}

struct SSHIdentity: Decodable, Equatable {
    let publicKey: String

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
    }
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

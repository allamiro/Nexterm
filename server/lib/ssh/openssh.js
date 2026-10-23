const crypto = require("crypto");

const CERT_TYPES = new Set([
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
]);

const DEFAULT_EXTENSIONS = [
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

const writeUint32 = (value) => {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value >>> 0);
    return buffer;
};

const writeUint64 = (value) => {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(value));
    return buffer;
};

const writeString = (value) => {
    const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
    return Buffer.concat([writeUint32(buffer.length), buffer]);
};

const readUint32 = (buffer, offset) => {
    if (offset + 4 > buffer.length) throw new Error("SSH certificate is malformed");
    return { value: buffer.readUInt32BE(offset), next: offset + 4 };
};

const readUint64 = (buffer, offset) => {
    if (offset + 8 > buffer.length) throw new Error("SSH certificate is malformed");
    return { value: buffer.readBigUInt64BE(offset), next: offset + 8 };
};

const readString = (buffer, offset) => {
    const length = readUint32(buffer, offset);
    const start = length.next;
    const end = start + length.value;
    if (end > buffer.length) throw new Error("SSH certificate is malformed");
    return { value: buffer.subarray(start, end), next: end };
};

const wrapBase64 = (buffer) => buffer.toString("base64").replace(/(.{70})/g, "$1\n");

const ed25519PublicBlob = (rawPublic) => Buffer.concat([
    writeString("ssh-ed25519"),
    writeString(rawPublic),
]);

const publicKeyLine = (rawPublic, comment = "nexterm") =>
    `ssh-ed25519 ${ed25519PublicBlob(rawPublic).toString("base64")} ${comment}`;

const keyObjectFromRaw = (seed, rawPublic) => crypto.createPrivateKey({
    key: {
        kty: "OKP",
        crv: "Ed25519",
        d: seed.toString("base64url"),
        x: rawPublic.toString("base64url"),
    },
    format: "jwk",
});

const rawFromKeyObject = (keyObject) => {
    const jwk = keyObject.export({ format: "jwk" });
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.x) {
        throw new Error("Only Ed25519 CA keys can sign certificates locally");
    }
    return {
        seed: Buffer.from(jwk.d, "base64url"),
        rawPublic: Buffer.from(jwk.x, "base64url"),
    };
};

const encodeOpenSshPrivateKey = (seed, rawPublic, comment = "nexterm") => {
    const check = crypto.randomBytes(4);
    let secret = Buffer.concat([
        check,
        check,
        writeString("ssh-ed25519"),
        writeString(rawPublic),
        writeString(Buffer.concat([seed, rawPublic])),
        writeString(comment),
    ]);
    let pad = 1;
    while (secret.length % 8 !== 0) {
        secret = Buffer.concat([secret, Buffer.from([pad])]);
        pad += 1;
    }

    const body = Buffer.concat([
        Buffer.from("openssh-key-v1\0"),
        writeString("none"),
        writeString("none"),
        writeString(""),
        writeUint32(1),
        writeString(ed25519PublicBlob(rawPublic)),
        writeString(secret),
    ]);

    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapBase64(body)}\n-----END OPENSSH PRIVATE KEY-----\n`;
};

const parseOpenSshPrivateKey = (material) => {
    const trimmed = String(material || "").trim();
    const match = trimmed.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+)-----END OPENSSH PRIVATE KEY-----/);
    if (!match) return null;

    const body = Buffer.from(match[1].replace(/\s/g, ""), "base64");
    const magic = Buffer.from("openssh-key-v1\0");
    if (!body.subarray(0, magic.length).equals(magic)) {
        throw new Error("SSH CA private key is not an OpenSSH key");
    }

    let offset = magic.length;
    const cipher = readString(body, offset);
    offset = cipher.next;
    const kdf = readString(body, offset);
    offset = kdf.next;
    const kdfOptions = readString(body, offset);
    offset = kdfOptions.next;
    if (cipher.value.toString() !== "none" || kdf.value.toString() !== "none") {
        throw new Error("The CA private key must not have a passphrase");
    }

    const count = readUint32(body, offset);
    offset = count.next;
    if (count.value < 1) throw new Error("SSH CA private key does not contain a key");
    const embeddedPublic = readString(body, offset);
    offset = embeddedPublic.next;
    for (let index = 1; index < count.value; index += 1) {
        offset = readString(body, offset).next;
    }
    const secret = readString(body, offset).value;
    const first = readUint32(secret, 0);
    const second = readUint32(secret, first.next);
    if (first.value !== second.value) throw new Error("SSH CA private key is malformed");

    let secretOffset = second.next;
    const keyType = readString(secret, secretOffset);
    secretOffset = keyType.next;
    if (keyType.value.toString() !== "ssh-ed25519") {
        throw new Error("Only Ed25519 CA keys can sign certificates locally");
    }
    const rawPublic = readString(secret, secretOffset);
    secretOffset = rawPublic.next;
    const rawPrivate = readString(secret, secretOffset);
    if (rawPrivate.value.length !== 64) throw new Error("SSH CA private key is malformed");

    const seed = rawPrivate.value.subarray(0, 32);
    const publicFromPrivate = rawPrivate.value.subarray(32);
    if (!publicFromPrivate.equals(rawPublic.value)) throw new Error("SSH CA private key is malformed");
    if (embeddedPublic.value.length && !embeddedPublic.value.equals(ed25519PublicBlob(rawPublic.value))) {
        throw new Error("SSH CA private key is malformed");
    }

    return keyObjectFromRaw(seed, rawPublic.value);
};

const loadEd25519PrivateKey = (material) => {
    const openssh = parseOpenSshPrivateKey(material);
    if (openssh) return openssh;
    try {
        const key = crypto.createPrivateKey(String(material || "").trim());
        rawFromKeyObject(key);
        return key;
    } catch (error) {
        if (String(error.message || "").includes("Ed25519") || String(error.message || "").includes("passphrase")) throw error;
        throw new Error("SSH CA private key could not be read");
    }
};

const publicKeyFromPrivate = (material) => {
    const { rawPublic } = rawFromKeyObject(loadEd25519PrivateKey(material));
    return publicKeyLine(rawPublic, "nexterm-ca");
};

const generateEd25519KeyPair = (comment = "nexterm-session") => {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    const { seed, rawPublic } = rawFromKeyObject(privateKey);
    return {
        privateKey: encodeOpenSshPrivateKey(seed, rawPublic, comment),
        publicKey: publicKeyLine(rawPublic, comment),
        rawPublic,
    };
};

const signUserCertificate = ({
    caPrivateKey,
    rawPublic,
    keyId,
    principals,
    serial,
    validAfter,
    validBefore,
    sourceAddress = null,
    extensions = DEFAULT_EXTENSIONS,
}) => {
    const signer = typeof caPrivateKey === "string" ? loadEd25519PrivateKey(caPrivateKey) : caPrivateKey;
    const { rawPublic: caRawPublic } = rawFromKeyObject(signer);
    const caPublicBlob = ed25519PublicBlob(caRawPublic);
    const principalsBlob = Buffer.concat(principals.map((principal) => writeString(principal)));
    const critical = sourceAddress
        ? Buffer.concat([
            writeString("source-address"),
            writeString(writeString(sourceAddress)),
        ])
        : Buffer.alloc(0);
    const extensionBlob = Buffer.concat(extensions.map((name) => Buffer.concat([
        writeString(name),
        writeString(""),
    ])));

    const body = Buffer.concat([
        writeString("ssh-ed25519-cert-v01@openssh.com"),
        writeString(crypto.randomBytes(32)),
        writeString(rawPublic),
        writeUint64(serial),
        writeUint32(1),
        writeString(keyId),
        writeString(principalsBlob),
        writeUint64(validAfter),
        writeUint64(validBefore),
        writeString(critical),
        writeString(extensionBlob),
        writeString(""),
        writeString(caPublicBlob),
    ]);

    const signature = crypto.sign(null, body, signer);
    const signatureBlob = Buffer.concat([
        writeString("ssh-ed25519"),
        writeString(signature),
    ]);
    const certificate = Buffer.concat([body, writeString(signatureBlob)]);
    return `ssh-ed25519-cert-v01@openssh.com ${certificate.toString("base64")} ${keyId}`;
};

const certificateLine = (text) => String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line && !line.startsWith("#"));

const normalizeCertificate = (text) => {
    const line = certificateLine(text);
    if (!line) throw new Error("SSH certificate is empty");
    const match = line.match(/^(\S+)\s+([A-Za-z0-9+/=]+)(?:\s+(\S+))?$/);
    if (!match || !CERT_TYPES.has(match[1])) throw new Error("SSH certificate is not an OpenSSH user certificate");
    const decoded = Buffer.from(match[2], "base64");
    if (!decoded.length) throw new Error("SSH certificate is malformed");
    const type = readString(decoded, 0);
    if (type.value.toString() !== match[1]) throw new Error("SSH certificate is malformed");
    return match[3] ? `${match[1]} ${match[2]} ${match[3]}` : `${match[1]} ${match[2]}`;
};

const readNameList = (buffer) => {
    const names = [];
    let offset = 0;
    while (offset < buffer.length) {
        const item = readString(buffer, offset);
        names.push(item.value.toString());
        offset = item.next;
    }
    return names;
};

const readOptionMap = (buffer) => {
    const options = {};
    let offset = 0;
    while (offset < buffer.length) {
        const name = readString(buffer, offset);
        offset = name.next;
        const data = readString(buffer, offset);
        offset = data.next;
        const inner = data.value.length ? readString(data.value, 0).value.toString() : "";
        options[name.value.toString()] = inner;
    }
    return options;
};

const describeCertificate = (text) => {
    const normalized = normalizeCertificate(text);
    if (!normalized.startsWith("ssh-ed25519-cert-v01@openssh.com ")) {
        return { keyId: normalized.split(/\s+/)[2] || null, principals: [], serial: null, signatureValid: null };
    }

    const body = Buffer.from(normalized.split(/\s+/)[1], "base64");
    let offset = 0;
    offset = readString(body, offset).next;
    offset = readString(body, offset).next;
    offset = readString(body, offset).next;
    const serial = readUint64(body, offset);
    offset = serial.next;
    offset = readUint32(body, offset).next;
    const keyId = readString(body, offset);
    offset = keyId.next;
    const principals = readString(body, offset);
    offset = principals.next;
    const validAfter = readUint64(body, offset);
    offset = validAfter.next;
    const validBefore = readUint64(body, offset);
    offset = validBefore.next;
    const critical = readString(body, offset);
    offset = critical.next;
    offset = readString(body, offset).next;
    offset = readString(body, offset).next;
    const signatureKey = readString(body, offset);
    offset = signatureKey.next;
    const signedEnd = offset;
    const signature = readString(body, offset);
    const signatureParts = readString(signature.value, 0);
    const signatureType = signatureParts.value.toString();
    const signatureValue = readString(signature.value, signatureParts.next).value;
    const caType = readString(signatureKey.value, 0);
    const caRaw = readString(signatureKey.value, caType.next).value;
    const caPublic = crypto.createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: caRaw.toString("base64url") },
        format: "jwk",
    });
    const options = readOptionMap(critical.value);

    return {
        serial: serial.value.toString(),
        keyId: keyId.value.toString(),
        principals: readNameList(principals.value),
        validAfter: Number(validAfter.value),
        validBefore: Number(validBefore.value),
        sourceAddress: options["source-address"] || null,
        signatureValid: signatureType === "ssh-ed25519"
            && crypto.verify(null, body.subarray(0, signedEnd), caPublic, signatureValue),
    };
};

module.exports = {
    DEFAULT_EXTENSIONS,
    generateEd25519KeyPair,
    encodeOpenSshPrivateKey,
    loadEd25519PrivateKey,
    publicKeyFromPrivate,
    signUserCertificate,
    normalizeCertificate,
    describeCertificate,
};

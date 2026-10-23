const net = require("net");

const asArray = (value) => {
    if (Array.isArray(value)) return value;
    if (typeof value === "string" && value.trim()) {
        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }
    return [];
};

const addPrincipal = (principals, value) => {
    const principal = String(value || "").trim();
    if (!principal) return;
    if (principal.length > 128) throw new Error("SSH principal is too long");
    if (/[\u0000-\u001f,\s]/.test(principal)) throw new Error("SSH principal contains invalid characters");
    if (!principals.includes(principal)) principals.push(principal);
};

const resolvePrincipals = ({ username, groups = [], groupPrincipalMappings = [], extraPrincipals = [] }) => {
    const principals = [];
    addPrincipal(principals, username);
    const groupSet = new Set(asArray(groups).map((group) => String(group)));
    for (const mapping of asArray(groupPrincipalMappings)) {
        if (!mapping || !groupSet.has(String(mapping.group))) continue;
        for (const principal of asArray(mapping.principals)) addPrincipal(principals, principal);
    }
    for (const principal of asArray(extraPrincipals)) addPrincipal(principals, principal);
    if (!principals.length) throw new Error("A username or principal is required to issue an SSH certificate");
    if (principals.length > 32) throw new Error("Too many SSH principals");
    return principals;
};

const renderKeyId = (template, values) => {
    const rendered = String(template || "{{username}}")
        .replaceAll("{{username}}", values.username || "")
        .replaceAll("{{account}}", values.account || "")
        .replaceAll("{{server}}", values.server || "")
        .replaceAll("{{host}}", values.host || "")
        .trim();
    const keyId = rendered || values.username || "nexterm";
    if (keyId.length > 128 || /[\u0000-\u001f]/.test(keyId)) throw new Error("SSH certificate key id is invalid");
    return keyId;
};

const clampTtl = (ttlSeconds) => {
    const value = Number(ttlSeconds);
    if (!Number.isFinite(value)) return 300;
    return Math.min(86400, Math.max(30, Math.floor(value)));
};

const normalizeSourceAddress = (value) => {
    if (!value) return null;
    const parts = String(value).split(",").map((part) => part.trim()).filter(Boolean);
    if (!parts.length) return null;
    return parts.map((part) => {
        const [address, prefix] = part.split("/");
        const version = net.isIP(address);
        if (!version || part.split("/").length > 2) throw new Error("SSH certificate source address is invalid");
        const bits = prefix === undefined ? (version === 4 ? 32 : 128) : Number(prefix);
        const max = version === 4 ? 32 : 128;
        if (!Number.isInteger(bits) || bits < 0 || bits > max) throw new Error("SSH certificate source address is invalid");
        return `${address}/${bits}`;
    }).join(",");
};

module.exports = {
    asArray,
    resolvePrincipals,
    renderKeyId,
    clampTtl,
    normalizeSourceAddress,
};

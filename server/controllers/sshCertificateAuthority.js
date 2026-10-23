const { Op } = require("sequelize");
const SshCertificateAuthority = require("../models/SshCertificateAuthority");
const OrganizationMember = require("../models/OrganizationMember");
const { hasAccountPermission } = require("../utils/permission");
const { Permission } = require("../permissions/registry");
const { publicKeyFromPrivate } = require("../lib/ssh/openssh");
const { normalizeSourceAddress, asArray } = require("../lib/ssh/principals");
const logger = require("../utils/logger");

const canManage = (accountId) => hasAccountPermission(accountId, Permission.SETTINGS_AUTH_PROVIDERS);

const record = (authority) => (authority?.get ? authority.get({ plain: true }) : authority);

const sanitize = (authority) => {
    const value = record(authority);
    const config = { ...(value.config || {}) };
    return {
        id: value.id,
        name: value.name,
        backend: value.backend,
        enabled: value.enabled !== false,
        organizationId: value.organizationId || null,
        ttlSeconds: value.ttlSeconds,
        sourceAddress: value.sourceAddress || "",
        extraPrincipals: asArray(value.extraPrincipals),
        groupPrincipalMappings: asArray(value.groupPrincipalMappings),
        keyIdTemplate: value.keyIdTemplate || "{{username}}",
        config,
        hasSecret: Boolean(value.secret || value.secretEncrypted),
    };
};

const validateBackend = (backend, config = {}, secret, { creating }) => {
    if (backend === "local") {
        if (creating && !secret) return "A CA private key is required";
        if (secret) {
            try {
                return { publicKey: publicKeyFromPrivate(secret) };
            } catch (error) {
                return error.message;
            }
        }
        return {};
    }
    if (backend === "vault" && (!config.address || !config.mount || !config.role)) return "Vault address, mount, and role are required";
    if (backend === "step" && !config.url) return "A step-ca URL is required";
    if (backend === "webhook" && !config.url) return "A webhook URL is required";
    if (creating && backend !== "webhook" && !secret) return "A signing token is required";
    return {};
};

const applyConfig = (backend, config, secret, existingConfig = {}) => {
    const next = { ...existingConfig, ...(config || {}) };
    delete next.publicKey;
    if (backend === "local") {
        if (secret) next.publicKey = publicKeyFromPrivate(secret);
        else if (existingConfig.publicKey) next.publicKey = existingConfig.publicKey;
    }
    return next;
};

const listCertificateAuthorities = async (accountId) => {
    const manage = await canManage(accountId);
    const memberships = await OrganizationMember.findAll({ where: { accountId, status: "active" }, attributes: ["organizationId"] });
    const organizationIds = memberships.map((membership) => membership.organizationId);
    const where = manage ? {} : {
        enabled: true,
        [Op.or]: [
            { organizationId: null },
            ...(organizationIds.length ? [{ organizationId: { [Op.in]: organizationIds } }] : []),
        ],
    };
    const authorities = await SshCertificateAuthority.findAll({ where, order: [["name", "ASC"]], raw: false });
    return authorities.map(sanitize);
};

const createCertificateAuthority = async (accountId, body) => {
    if (!(await canManage(accountId))) return { code: 403, message: "You don't have permission to manage SSH certificate authorities" };
    let sourceAddress = null;
    try {
        sourceAddress = normalizeSourceAddress(body.sourceAddress);
    } catch (error) {
        return { code: 400, message: error.message };
    }
    const checked = validateBackend(body.backend, body.config, body.secret, { creating: true });
    if (typeof checked === "string") return { code: 400, message: checked };

    const authority = await SshCertificateAuthority.create({
        name: body.name,
        backend: body.backend,
        enabled: body.enabled !== false,
        organizationId: body.organizationId || null,
        ttlSeconds: body.ttlSeconds || 300,
        sourceAddress,
        extraPrincipals: body.extraPrincipals || [],
        groupPrincipalMappings: body.groupPrincipalMappings || [],
        keyIdTemplate: body.keyIdTemplate || "{{username}}",
        config: applyConfig(body.backend, body.config, body.secret),
        secret: body.secret || null,
    });
    logger.info("SSH certificate authority created", { id: authority.id, backend: authority.backend });
    return sanitize(await SshCertificateAuthority.findByPk(authority.id, { raw: false }));
};

const updateCertificateAuthority = async (accountId, id, body) => {
    if (!(await canManage(accountId))) return { code: 403, message: "You don't have permission to manage SSH certificate authorities" };
    const authority = await SshCertificateAuthority.findByPk(id, { raw: false });
    if (!authority) return { code: 404, message: "SSH certificate authority was not found" };

    const backend = body.backend || authority.backend;
    const secret = body.secret === "" ? null : body.secret;
    const checked = validateBackend(backend, body.config || authority.config, secret, { creating: false });
    if (typeof checked === "string") return { code: 400, message: checked };
    if (body.sourceAddress !== undefined) {
        try {
            authority.sourceAddress = normalizeSourceAddress(body.sourceAddress);
        } catch (error) {
            return { code: 400, message: error.message };
        }
    }

    if (body.name !== undefined) authority.name = body.name;
    authority.backend = backend;
    if (body.enabled !== undefined) authority.enabled = body.enabled;
    if (body.organizationId !== undefined) authority.organizationId = body.organizationId || null;
    if (body.ttlSeconds !== undefined) authority.ttlSeconds = body.ttlSeconds;
    if (body.extraPrincipals !== undefined) authority.extraPrincipals = body.extraPrincipals;
    if (body.groupPrincipalMappings !== undefined) authority.groupPrincipalMappings = body.groupPrincipalMappings;
    if (body.keyIdTemplate !== undefined) authority.keyIdTemplate = body.keyIdTemplate;
    if (body.config !== undefined || secret) authority.config = applyConfig(backend, body.config, secret, authority.config || {});
    if (secret) authority.secret = secret;
    await authority.save();
    logger.info("SSH certificate authority updated", { id: authority.id, backend: authority.backend });
    return sanitize(await SshCertificateAuthority.findByPk(authority.id, { raw: false }));
};

const deleteCertificateAuthority = async (accountId, id) => {
    if (!(await canManage(accountId))) return { code: 403, message: "You don't have permission to manage SSH certificate authorities" };
    const authority = await SshCertificateAuthority.findByPk(id, { raw: false });
    if (!authority) return { code: 404, message: "SSH certificate authority was not found" };
    await authority.destroy();
    logger.info("SSH certificate authority deleted", { id, name: authority.name });
    return { success: true };
};

module.exports = {
    listCertificateAuthorities,
    createCertificateAuthority,
    updateCertificateAuthority,
    deleteCertificateAuthority,
};

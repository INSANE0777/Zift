const { RULES } = require('./rules/definitions');

class SafetyEngine {
    constructor() {
        this.results = [];
    }

    evaluate(packageFacts, lifecycleFiles, manifest = null) {
        let findings = [];

        // 1. Process Manifest Violations (if manifest exists)
        if (manifest) {
            const manifestFails = this.validateManifest(packageFacts, manifest);
            if (manifestFails.length > 0) {
                packageFacts.facts.MANIFEST_MISMATCH = manifestFails;
            }
        }

        // 2. Process each rule
        for (const rule of RULES) {
            const match = this.matchRule(rule, packageFacts, lifecycleFiles);
            if (match) {
                findings.push(match);
            }
        }

        // Sort by score (desc) and then by priority (desc)
        findings.sort((a, b) => (b.score - a.score) || (b.priority - a.priority));

        return findings;
    }

    validateManifest(packageFacts, manifest) {
        const { facts } = packageFacts;
        const violations = [];

        // Check Network
        if (manifest.capabilities && manifest.capabilities.network) {
            const networkFacts = facts.NETWORK_SINK || [];
            if (!manifest.capabilities.network.enabled && networkFacts.length > 0) {
                networkFacts.forEach(f => violations.push({ ...f, context: 'UNAUTHORIZED_NETWORK_SINK' }));
            }
        }

        // Check Shell
        if (manifest.capabilities && manifest.capabilities.shell) {
            const shellFacts = facts.SHELL_EXECUTION || [];
            if (!manifest.capabilities.shell.enabled && shellFacts.length > 0) {
                shellFacts.forEach(f => violations.push({ ...f, context: 'UNAUTHORIZED_SHELL_EXECUTION' }));
            }
        }

        // Check Filesystem (Write)
        if (manifest.capabilities && manifest.capabilities.filesystem) {
            const writeFacts = facts.FILE_WRITE_STARTUP || [];
            if (!manifest.capabilities.filesystem.write && writeFacts.length > 0) {
                writeFacts.forEach(f => violations.push({ ...f, context: 'UNAUTHORIZED_FILE_WRITE' }));
            }
        }

        return violations;
    }

    matchRule(rule, packageFacts, lifecycleFiles) {
        const { facts } = packageFacts;
        const triggers = [];
        let baseScore = rule.baseScore;
        let multiplier = 1;

        // Check required facts
        for (const req of rule.requires) {
            let matchedFacts = (facts[req] || []).map(f => ({ ...f, type: req }));

            // Handle virtual requirements (LIFECYCLE_CONTEXT)
            if (req === 'LIFECYCLE_CONTEXT' && matchedFacts.length === 0) {
                const virtualMatch = triggers.some(t => {
                    if (lifecycleFiles instanceof Set) return lifecycleFiles.has(t.file);
                    if (Array.isArray(lifecycleFiles)) return lifecycleFiles.includes(t.file);
                    return false;
                });
                if (virtualMatch) {
                    matchedFacts = [{ type: 'LIFECYCLE_CONTEXT', virtual: true }];
                }
            }

            if (matchedFacts.length === 0) return null;

            // v5.3 Sequence Matching: Ensure facts occur in specified order (if rule has .sequence)
            if (rule.sequence) {
                const reqIndex = rule.requires.indexOf(req);
                if (reqIndex > 0) {
                    const prevReq = rule.requires[reqIndex - 1];
                    const prevTriggers = triggers.filter(t => t.type === prevReq);

                    // Filter current matches to only those that happen AFTER a previous trigger
                    matchedFacts = matchedFacts.filter(curr => {
                        return prevTriggers.some(prev => curr.line >= prev.line);
                    });
                }
            }

            if (matchedFacts.length === 0) return null;
            triggers.push(...matchedFacts);
        }

        // Check optional facts for bonuses
        if (rule.optional) {
            for (const opt of rule.optional) {
                const matchedOpts = facts[opt] || [];
                if (matchedOpts.length > 0) {
                    triggers.push(...matchedOpts.map(f => ({ ...f, type: opt })));
                    baseScore += 20;
                }
            }
        }

        // Check for Lifecycle Context Fact (Virtual or Actual)
        const isInLifecycle = triggers.some(t => lifecycleFiles.has(t.file)) || (facts['LIFECYCLE_CONTEXT'] && facts['LIFECYCLE_CONTEXT'].length > 0);
        if (isInLifecycle) {
            multiplier *= 2.0;
        }

        // Encoder Multiplier (1.5x)
        const hasEncoder = facts['ENCODER_USE'] && facts['ENCODER_USE'].length > 0;
        if (hasEncoder) {
            multiplier *= 1.5;
        }

        // Cluster Bonus: Source + Sink
        const hasSource = triggers.some(t => t.type.includes('READ') || t.type.includes('ACCESS'));
        const hasSink = triggers.some(t => t.type.includes('SINK') || t.type === 'DYNAMIC_EXECUTION' || t.type === 'SHELL_EXECUTION' || t.type === 'DYNAMIC_REQUIRE' || t.type === 'WIPER_OPERATION' || t.type === 'REVERSE_SHELL_BEHAVIOR');
        if (hasSource && hasSink) {
            baseScore += 40;
        }

        let finalScore = baseScore * multiplier;

        // Severe Cluster: SENSITIVE_READ + Dangerous Sink + lifecycleContext = Critical (100)
        const isSensitiveRead = triggers.some(t => t.type === 'ENV_READ' || t.type === 'FILE_READ_SENSITIVE' || t.type === 'CICD_SECRET_ACCESS');
        const isDangerousSink = triggers.some(t => t.type === 'NETWORK_SINK' || t.type === 'DNS_SINK' || t.type === 'RAW_SOCKET_SINK' || t.type === 'SHELL_EXECUTION' || t.type === 'WEBHOOK_SINK' || t.type === 'WIPER_OPERATION' || t.type === 'REVERSE_SHELL_BEHAVIOR');
        if (isSensitiveRead && isDangerousSink && isInLifecycle) {
            finalScore = 100;
        }

        return {
            id: rule.id,
            alias: rule.alias,
            name: rule.name,
            priority: rule.priority || 1,
            score: Math.min(finalScore, 100),
            triggers: triggers,
            description: rule.description,
            isLifecycle: isInLifecycle
        };
    }
}

module.exports = SafetyEngine;

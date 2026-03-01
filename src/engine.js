const { RULES } = require('./rules/definitions');

class SafetyEngine {
    constructor() {
        this.results = [];
    }

    evaluate(packageFacts, lifecycleFiles) {
        let findings = [];

        // Process each rule
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

    matchRule(rule, packageFacts, lifecycleFiles) {
        const { facts } = packageFacts;
        const triggers = [];
        let baseScore = rule.baseScore;
        let multiplier = 1;

        // Check required facts
        for (const req of rule.requires) {
            let matchedFacts = facts[req] || [];

            // Specialist Rule: Startup Mod (ZFT-012) requires specific file paths (now explicit in definitions but engine may still help)
            // But per review, we should aim for explicit facts.
            // ZFT-012 now just requires FILE_WRITE_STARTUP. Simple.

            if (matchedFacts.length === 0) return null; // Rule not matched
            triggers.push(...matchedFacts.map(f => ({ ...f, type: req })));
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
        const hasSink = triggers.some(t => t.type.includes('SINK') || t.type === 'DYNAMIC_EXECUTION' || t.type === 'SHELL_EXECUTION' || t.type === 'DYNAMIC_REQUIRE');
        if (hasSource && hasSink) {
            baseScore += 40;
        }

        let finalScore = baseScore * multiplier;

        // Severe Cluster: SENSITIVE_READ + Dangerous Sink + lifecycleContext = Critical (100)
        const isSensitiveRead = triggers.some(t => t.type === 'ENV_READ' || t.type === 'FILE_READ_SENSITIVE');
        const isDangerousSink = triggers.some(t => t.type === 'NETWORK_SINK' || t.type === 'DNS_SINK' || t.type === 'RAW_SOCKET_SINK' || t.type === 'SHELL_EXECUTION');
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

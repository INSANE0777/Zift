const { RULES } = require('./rules/definitions');

class SafetyEngine {
    constructor() {
        this.results = [];
    }

    evaluate(packageFacts, lifecycleFiles) {
        const findings = [];

        // Process each rule
        for (const rule of RULES) {
            const match = this.matchRule(rule, packageFacts, lifecycleFiles);
            if (match) {
                findings.push(match);
            }
        }

        return findings;
    }

    matchRule(rule, packageFacts, lifecycleFiles) {
        const { facts } = packageFacts;
        const triggers = [];
        let baseScore = rule.baseScore;
        let multiplier = 1;

        // Check required facts
        for (const req of rule.requires) {
            const matchedFacts = facts[req] || [];
            if (matchedFacts.length === 0) return null; // Rule not matched
            triggers.push(...matchedFacts.map(f => ({ ...f, type: req })));
        }

        // Check optional facts for bonuses
        if (rule.optional) {
            for (const opt of rule.optional) {
                const matchedOpts = facts[opt] || [];
                if (matchedOpts.length > 0) {
                    triggers.push(...matchedOpts.map(f => ({ ...f, type: opt })));
                    baseScore += 20; // Bonus for optional matches (e.g., obfuscation)
                }
            }
        }

        // Apply Lifecycle Multiplier (1.8x)
        const isInLifecycle = triggers.some(t => lifecycleFiles.has(t.file));
        if (isInLifecycle) {
            multiplier = 1.8;
        }

        // Cluster Bonus: Source + Sink
        const hasSource = triggers.some(t => t.type.includes('READ'));
        const hasSink = triggers.some(t => t.type.includes('SINK') || t.type === 'DYNAMIC_EXECUTION');
        if (hasSource && hasSink) {
            baseScore += 40;
        }

        let finalScore = baseScore * multiplier;

        // Lifecycle Guard: ENV_READ + NETWORK_SINK + lifecycleContext = min 85 (High)
        const isEnvRead = triggers.some(t => t.type === 'ENV_READ');
        const isNetworkSink = triggers.some(t => t.type === 'NETWORK_SINK');
        if (isEnvRead && isNetworkSink && isInLifecycle && finalScore < 85) {
            finalScore = 85;
        }

        return {
            id: rule.id,
            alias: rule.alias,
            name: rule.name,
            score: Math.min(finalScore, 100),
            triggers: triggers,
            description: rule.description,
            isLifecycle: isInLifecycle
        };
    }
}

module.exports = SafetyEngine;

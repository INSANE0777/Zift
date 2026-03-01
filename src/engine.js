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
            let matchedFacts = facts[req] || [];

            // Special case for dynamic require (which shares DYNAMIC_EXECUTION fact type)
            if (rule.alias === 'DYNAMIC_REQUIRE_DEPENDENCY') {
                matchedFacts = matchedFacts.filter(f => f.type === 'dynamic_require');
            } else if (req === 'DYNAMIC_EXECUTION') {
                matchedFacts = matchedFacts.filter(f => f.type !== 'dynamic_require');
            }

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

        // Apply Lifecycle Multiplier (2.0x for V2)
        const isInLifecycle = triggers.some(t => lifecycleFiles.has(t.file));
        if (isInLifecycle) {
            multiplier = 2.0;
        }

        // Encoder Multiplier (1.5x)
        const hasEncoder = facts['ENCODER_USE'] && facts['ENCODER_USE'].length > 0;
        if (hasEncoder) {
            multiplier *= 1.5;
        }

        // Cluster Bonus: Source + Sink
        const hasSource = triggers.some(t => t.type.includes('READ'));
        const hasSink = triggers.some(t => t.type.includes('SINK') || t.type === 'DYNAMIC_EXECUTION' || t.type === 'SHELL_EXECUTION');
        if (hasSource && hasSink) {
            baseScore += 40;
        }

        let finalScore = baseScore * multiplier;

        // Severe Cluster: ENV_READ + (NETWORK_SINK | SHELL_EXECUTION) + lifecycleContext = Critical (100)
        const isEnvRead = triggers.some(t => t.type === 'ENV_READ');
        const isDangerousSink = triggers.some(t => t.type === 'NETWORK_SINK' || t.type === 'SHELL_EXECUTION');
        if (isEnvRead && isDangerousSink && isInLifecycle) {
            finalScore = 100;
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

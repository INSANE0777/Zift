function levenshtein(s1, s2) {
    const scores = [];
    for (let i = 0; i <= s1.length; i++) {
        let lastValue = i;
        for (let j = 0; j <= s2.length; j++) {
            if (i === 0) {
                scores[j] = j;
            } else if (j > 0) {
                let newValue = scores[j - 1];
                if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
                    newValue = Math.min(Math.min(newValue, lastValue), scores[j]) + 1;
                }
                scores[j - 1] = lastValue;
                lastValue = newValue;
            }
        }
        if (i > 0) scores[s2.length] = lastValue;
    }
    return scores[s2.length];
}

const TOP_PACKAGES = [
    'react', 'vue', 'axios', 'express', 'lodash', 'moment', 'next', 'react-dom',
    'chalk', 'commander', 'fs-extra', 'glob', 'inquirer', 'jest', 'request',
    'typescript', 'webpack', 'babel-core', 'eslint', 'prettier'
];

function checkTyposquat(name) {
    if (!name || TOP_PACKAGES.includes(name)) return null;

    for (const top of TOP_PACKAGES) {
        const distance = levenshtein(name, top);
        if (distance === 1 || (distance === 2 && top.length >= 5)) {
            return {
                target: top,
                distance: distance
            };
        }
    }
    return null;
}

module.exports = { checkTyposquat };

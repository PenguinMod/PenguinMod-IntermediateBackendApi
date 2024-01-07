const Cast = require('./Cast.js');
const illegalWords = require("../illegalwords.js"); // js file that sets module.exports to an array of banned words

const CheckForIllegalWording = (...args) => {
    for (const argument of args) {
        for (const illegalWord of illegalWords.includingWords) {
            const checking = Cast.toString(argument)
                .toLowerCase()
                .replace(/[\s_\-!?\.#/\\,'"@$%^&*\(\)]+/gmi, '');
            if (checking.includes(illegalWord)) {
                return true;
            }
        }
        for (const illegalWebsite of illegalWords.illegalWebsites) {
            const checking = Cast.toString(argument)
                .toLowerCase()
                .replace(/[\s_\-!?#\\,'"@$%^&*]+/gmi, '');
            if (checking.includes(illegalWebsite)) {
                return true;
            }
        }
        for (const illegalWord of illegalWords.spacedOutWordsOnly) {
            const text = `${Cast.toString(argument).toLowerCase().trim()}`.split(' ');
            const checking = text.map(word => word.replace(/[\s_\-!?\.#/\\,'"@$%^&*\(\)]+/gmi, ''));
            if (checking.some(word => word.includes(illegalWord))) {
                return true;
            }
        }
    }
    return false;
};

const CheckForSlightlyIllegalWording = (...args) => {
    for (const argument of args) {
        for (const illegalWord of illegalWords.potentiallyUnsafeWords) {
            const checking = Cast.toString(argument)
                .toLowerCase()
                .replace(/[\s_\-!?\.#/\\,'"@$%^&*\(\)]+/gmi, '');
            if (checking.includes(illegalWord)) {
                return true;
            }
        }
        for (const illegalWord of illegalWords.potentiallyUnsafeWordsSpacedOut) {
            const text = `${Cast.toString(argument).toLowerCase().trim()}`.split(' ');
            const checking = text.map(word => word.replace(/[\s_\-!?\.#/\\,'"@$%^&*\(\)]+/gmi, ''));
            if (checking.some(word => word.includes(illegalWord))) {
                return true;
            }
        }
    }
    return false;
};

class ProfanityChecker {
    static containsUnsafeContent = CheckForIllegalWording;
    static containsPotentiallyUnsafeContent = CheckForSlightlyIllegalWording;
    static checkAndWarnPotentiallyUnsafeContent(text, type, location) {
        if (ProfanityChecker.containsPotentiallyUnsafeContent(text)) {
            ProfanityChecker.sendWarningLog(text, type, location);
        }
    }
    static sendHeatLog(text, type, location) {
        const body = JSON.stringify({
            embeds: [{
                title: `Filter Triggered`,
                color: 0xff0000,
                description: text,
                fields: [
                    {
                        name: "Type",
                        value: `\`${type}\``
                    },
                    {
                        name: "Location",
                        value: `${JSON.stringify(location)}`
                    }
                ],
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.HeatWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body
        });
    }
    static sendWarningLog(text, type, location) {
        const body = JSON.stringify({
            embeds: [{
                title: `Filter Detected Potentially Unsafe Content`,
                color: 0xffbb00,
                description: text,
                fields: [
                    {
                        name: "Type",
                        value: `\`${type}\``
                    },
                    {
                        name: "Location",
                        value: `${JSON.stringify(location)}`
                    }
                ],
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.HeatWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body
        });
    }
}

module.exports = ProfanityChecker;
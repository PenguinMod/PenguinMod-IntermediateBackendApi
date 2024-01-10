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

const illegalAnsi = '\x1b[31;1m'
const unsafeAnsi = '\x1b[33;1m'
const defaultAnsi = '\x1b[0m'
const splitString = text => {
    const resArray = []
    let lastEnd = 0
    for (const match of text.trim().matchAll(/[\s_\-!?\.#\/\\,'"@$%^&*\(\)]+/gmi)) {
        resArray.push(text.slice(lastEnd, match.index), match[0])
        lastEnd = match.index + match[0].length
    }
    resArray.push(text.slice(lastEnd))
    return resArray
}

class ProfanityChecker {
    static containsUnsafeContent = CheckForIllegalWording;
    static containsPotentiallyUnsafeContent = CheckForSlightlyIllegalWording;
    static checkAndWarnPotentiallyUnsafeContent(text, type, location) {
        if (ProfanityChecker.containsPotentiallyUnsafeContent(text)) {
            ProfanityChecker.sendWarningLog(text, type, location);
        }
    }
    static highlightOffendingTexts(text) {
        text = splitString(text)

        for (let i = 0; i < text.length; i += 2) {
            let word = text[i]
            for (const [type, illegalWord] of illegalWords.allSpacedTextChecks) {
                const indexOfSpaced = word.indexOf(illegalWord)
                if (indexOfSpaced > -1) {
                    let offender = word.slice(indexOfSpaced, illegalWord.length)
                    let left = word.slice(0, indexOfSpaced)
                    let right = word.slice(indexOfSpaced + illegalWord.length)
                    left += type === 'unsafe' 
                        ? unsafeAnsi
                        : illegalAnsi
                    offender += defaultAnsi
                    left += offender
                    left += right
                    word = left
                }
            }
            for (const [type, illegalWord] of illegalWords.allTextChecks) {
                const breaks = [word.length]
                let lastBreak = word.length
                let l = 0
                while (word <= illegalWord.length && text[i + (2 * l)]) {
                    breaks.push(lastBreak += word.length)
                    word += text[i + (2 * l)]
                    l++
                }

                const indexOfUnsafe = word.indexOf(illegalWord)
                if (indexOfUnsafe > -1) {
                    const ansiPrefix = type === 'unsafe' 
                        ? unsafeAnsi
                        : illegalAnsi
                    const breakIdx = breaks.findIndex(b => b > indexOfUnsafe)
                    // this should be the same as the previous, but it can just not be
                    // make sure we handle such a situation
                    let endBreakIdx = breaks.findIndex(b => b > indexOfUnsafe + word.length)
                    if (endBreakIdx < 0) endBreakIdx = breakIdx
                    let offender = word.slice(indexOfUnsafe, illegalWord.length)
                    let left = word.slice(0, indexOfUnsafe)
                    let right = word.slice(indexOfUnsafe + illegalWord.length)
                    left += ansiPrefix
                    breaks[breakIdx] += ansiPrefix.length
                    offender += defaultAnsi
                    breaks[endBreakIdx] += defaultAnsi.length
                    left += offender
                    left += right
                    word = left
                }

                lastBreak = 0
                for (const breakIdx in breaks) {
                    const breakItem = breaks[breakIdx]
                    text[i + (2 * breakIdx)] = word.slice(lastBreak, breakItem)
                    lastBreak = breakItem
                }
                word = text[i]
            }
        }

        return text.join('')
    }
    static sendHeatLog(text, type, location) {
        const body = JSON.stringify({
            embeds: [{
                title: `Filter Triggered`,
                color: 0xff0000,
                description: `\`\`\`ansi\n${ProfanityChecker.highlightOffendingTexts(text)}\n\`\`\``,
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
                description: `\`\`\`ansi\n${ProfanityChecker.highlightOffendingTexts(text)}\n\`\`\``,
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

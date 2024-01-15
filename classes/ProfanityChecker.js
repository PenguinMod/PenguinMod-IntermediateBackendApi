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
const findIndexOfBreak = (breaks, strIdx, alsoEquals) => {
    let length = 0
    for (const brIdx in breaks) {
        length += breaks[brIdx]
        if (length > strIdx || (alsoEquals && length === strIdx)) return brIdx
    }
    return -1
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
                const indexOfSpaced = word.toLowerCase().indexOf(illegalWord)
                const endOfSpaced = indexOfSpaced + illegalWord.length
                if (indexOfSpaced > -1) {
                    const ansiPrefix = type === 'unsafe' 
                        ? unsafeAnsi
                        : illegalAnsi
                    let offender = word.slice(indexOfSpaced, endOfSpaced)
                    let left = word.slice(0, indexOfSpaced)
                    let right = word.slice(endOfSpaced)
                    left += ansiPrefix
                    offender += defaultAnsi
                    left += offender
                    left += right
                    word = left
                }
            }
            for (const [type, illegalWord] of illegalWords.allTextChecks) {
                const breaks = [word.length]
                let l = 2
                let collapsedWord = word
                while (collapsedWord.length < illegalWord.length && text[i + l]) {
                    const str = text[i + l]
                    breaks.push(str.length)
                    collapsedWord += str
                    l += 2
                }

                const indexOfUnsafe = collapsedWord.toLowerCase().indexOf(illegalWord)
                const endOfUnsafe = indexOfUnsafe + illegalWord.length
                if (indexOfUnsafe > -1) {
                    const ansiPrefix = type === 'unsafe' 
                        ? unsafeAnsi
                        : illegalAnsi
                    const breakIdx = findIndexOfBreak(breaks, indexOfUnsafe)
                    // this should be the same as the previous, but it can just not be
                    // make sure we handle such a situation
                    const endBreakIdx = findIndexOfBreak(breaks, endOfUnsafe, true)
                    let offender = collapsedWord.slice(indexOfUnsafe, endOfUnsafe)
                    let left = collapsedWord.slice(0, indexOfUnsafe)
                    let right = collapsedWord.slice(endOfUnsafe)
                    breaks[breakIdx] += ansiPrefix.length
                    left += ansiPrefix
                    offender += defaultAnsi
                    breaks[endBreakIdx] += defaultAnsi.length
                    left += offender
                    left += right
                    collapsedWord = left

                    let lastBreak = 0
                    for (const breakItem of breaks) {
                        text[i] = collapsedWord.slice(lastBreak, lastBreak += breakItem)
                        i += 2
                    }

                    word = text[i]
                }

                if (!word) break;
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

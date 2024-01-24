// return;
require('dotenv').config();

const BlockedIPs = require("./blockedips.json"); // if you are cloning this, make sure to make this file

const fs = require("fs");
const jimp = require("jimp");
const JSZip = require("jszip");
const Database = require("./easy-json-database");
const Cast = require("./classes/Cast.js");
const os = require("os-utils");

const DEBUG_logAllFailedData = Cast.toBoolean(process.env.LogFailedData);

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const app = express();
const port = 8080;
let globalOperationCounter = 0;

const { encrypt, decrypt } = require("./utilities/encrypt.js");

const UserManager = require("./classes/UserManager.js");
// const UserStorage = require("./classes/UserStorage.js");
// const StorageSpace = new UserStorage(32000000, 3); // 32 mb per data piece, 3 keys per container
UserManager.load(); // should prevent logouts

const ProjectList = require("./classes/ProjectList.js");
const GenericList = require("./classes/GenericList.js");
const ReportList = require("./classes/ReportList.js");

const ProfanityChecker = require("./classes/ProfanityChecker.js");

const AdminAccountUsernames = new Database(`${__dirname}/admins.json`);
const ApproverUsernames = new Database(`${__dirname}/approvers.json`);

const GlobalRuntimeConfig = new Database(`${__dirname}/globalsettings.json`);

const UsernameIP = new Database(`${__dirname}/userips.json`);

// UserManager.setCode('debug', 'your-mom');

function EncryptArray(array) {
    const na = [];
    for (const value of array) {
        const encrypted = encrypt(value);
        na.push(encrypted);
    }
    return na;
}
function DecryptArray(array) {
    const na = [];
    for (const value of array) {
        const decrypted = decrypt(value);
        na.push(decrypted);
    }
    return na;
}
function SafeJSONParse(json) {
    try {
        return JSON.parse(json);
    } catch {
        return {};
    }
}
function RandomArrayItem(arr) {
    const rng = Math.round(Math.random() * (arr.length - 1));
    return arr[rng];
}

function Deprecation(res, reason = "") { // if an endpoint is deprecated, use this.
    res.status(400);
    res.header("Content-Type", 'application/json');
    res.json({
        error: "Deprecated Endpoint",
        reason
    });
}
function escapeXML(unsafe) {
    unsafe = String(unsafe);
    return unsafe.replace(/[<>&'"\n]/g, c => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            case '\n': return '&#10;'
        }
    });
};

/**
 * Returns either a JSZip instance or null.
 * @param {Buffer} buffer 
 * @param {JSZip.JSZipLoadOptions} options 
 * @returns {Promise<JSZip?>}
 */
const safeZipParse = (buffer, options) => {
    return new Promise((resolve) => {
        if (!buffer) return resolve();
        JSZip.loadAsync(buffer, options).then(zip => {
            resolve(zip);
        }).catch(() => {
            resolve();
        });
    });
};

const illegalExtensionsList = require("./illegalextensions.json");
const checkExtensionIsAllowed = (extension, isUrl) => {
    if (!extension) return true;
    let propertyName = "id";
    if (isUrl) {
        propertyName = "url";
    }
    const extensionsConfig = illegalExtensionsList[propertyName];
    const isIncluded = extensionsConfig.items.includes(extension);
    const isBlacklist = extensionsConfig.useAsWhitelist !== true;
    if (isBlacklist && isIncluded) {
        return false;
    }
    if (!isBlacklist && isIncluded) {
        return true;
    }
    if (!isBlacklist && !isIncluded) {
        return false;
    }
    return true; // isBlacklist and isntIncluded
};

app.use(cors({
    origin: '*',
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}));
app.use(bodyParser.urlencoded({
    limit: process.env.ServerSize,
    extended: false
}));
app.use(bodyParser.json({ limit: process.env.ServerSize }));
app.use((req, res, next) => {
    if (BlockedIPs.includes(req.ip)) return res.sendStatus(403);
    const encodedIp = Buffer.from(Cast.toString(req.ip), 'utf8').toString('hex');
    const username = UsernameIP.get(encodedIp) || 'Unknown';
    console.log(`${req.ip} - (${username}): ${req.originalUrl}`);
    next();
});
app.set('trust proxy', 1);
app.use(rateLimit({
    validate: {
        trustProxy: true,
        xForwardedForHeader: true,
    },
    windowMs: 5000,  // 150 requests per 5 seconds
    limit: 150,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
}));

app.get('/', async function (_, res) { // just basic stuff. returns the home page
    res.redirect('https://penguinmod.com');
});
app.get('/robots.txt', async function (_, res) { // more basic stuff!!!!! returns robots.txt
    res.sendFile(path.join(__dirname, './robots.txt'));
});

// get API metadata
app.get('/api', async function (_, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.sendFile(path.join(__dirname, './metadata.json'));
});
// PING COMMAND TO CHECK IF API IS WORKING (LOL)
app.get('/api/ping', async function (_, res) {
    res.send("Pong!")
});
const projectTemplate = fs.readFileSync('./project.html').toString();
app.get('/:id', async function (req, res) {
    const db = new Database(`${__dirname}/projects/published.json`);
    const json = db.get(String(req.params.id));
    if (!json) {
        res.sendFile(path.join(__dirname, './404-noproject.html'));
        return;
    }
    res.status(200);
    let html = projectTemplate
    for (const prop in json) {
        html = html.replaceAll(`{project.${prop}}`, escapeXML(json[prop]));
    }
    res.send(html);
});

// profile stuff
const GenerateProfileJSON = (username, includeBio) => {
    const rawBadges = UserManager.getProperty(username, "badges");
    const badges = Array.isArray(rawBadges) ? rawBadges : [];
    const isDonator = badges.includes('donator');

    let rank = UserManager.getProperty(username, "rank");
    if (typeof rank !== "number") rank = 0;
    const signInDate = UserManager.getProperty(username, "firstLogin") || Date.now();
    const projectsDatabase = new Database(`${__dirname}/projects/published.json`);
    const userProjects = projectsDatabase.all()
        .map(value => { return value.data })
        .filter(project => (project.owner === username));
    const canRequestRankUp = (userProjects.length > 3 // if we have 3 projects and
        && (Date.now() - signInDate) >= 4.32e+8) // first signed in 5 days ago
        || badges.length > 0; // or we have a badge

    const followers = UserManager.getFollowers(username);

    let myFeaturedProject = UserManager.getProperty(username, "myFeaturedProject");
    if (typeof myFeaturedProject !== "number") myFeaturedProject = null;
    let myFeaturedProjectTitle = UserManager.getProperty(username, "myFeaturedProjectTitle");
    if (typeof myFeaturedProjectTitle !== "number") myFeaturedProjectTitle = null;

    const isBanned = UserManager.isBanned(username);
    let bio = '';
    if (!isBanned && includeBio) {
        bio = UserManager.getProperty(username, "profileBio");
    }

    return {
        username,
        admin: AdminAccountUsernames.get(username),
        approver: ApproverUsernames.get(username),
        banned: isBanned, // skipped in /profile but provided in /usernameFromCode
        badges,
        donator: isDonator,
        rank,
        bio,
        myFeaturedProject,
        myFeaturedProjectTitle,
        followers: followers.length,
        canrankup: canRequestRankUp && rank === 0,
        viewable: userProjects.length > 0,
        projects: userProjects.length // we check projects anyways so might aswell
    };
};
app.get('/api/users/profile', async function (req, res) { // check if user is banned
    const username = Cast.toString(req.query.username);
    const includeBio = Cast.toBoolean(req.query.bio);
    if (typeof username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NoUserSpecified" });
        return;
    }
    if (UserManager.isBanned(username)) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(GenerateProfileJSON(username, includeBio));
});
app.post('/api/users/requestRankUp', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const username = Cast.toString(packet.username);
    const rawBadges = UserManager.getProperty(username, "badges");
    const badges = Array.isArray(rawBadges) ? rawBadges : [];

    let rank = UserManager.getProperty(username, "rank");
    if (typeof rank !== "number") rank = 0;
    if (rank !== 0) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "AlreadyRankedHighest" });
        return;
    }
    const signInDate = UserManager.getProperty(username, "firstLogin") || Date.now();
    const projectsDatabase = new Database(`${__dirname}/projects/published.json`);
    const userProjects = projectsDatabase.all()
        .map(value => { return value.data })
        .filter(project => (project.owner === username));
    const canRequestRankUp = (userProjects.length > 3 // if we have 3 projects and
        && (Date.now() - signInDate) >= 4.32e+8) // first signed in 5 days ago
        || badges.length > 0; // or we have a badge
    if (!canRequestRankUp) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Ineligble" });
        return;
    }
    UserManager.setProperty(username, "rank", 1);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// security stuff i guess :idk_man:
app.get('/api/users/isBanned', async function (req, res) { // check if user is banned
    if (typeof req.query.username != "string") {
        res.status(400)
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidRequest" })
        return
    }
    res.status(200)
    res.header("Content-Type", 'application/json');
    res.json({ "banned": UserManager.isBanned(req.query.username) })
});
app.get('/api/users/assignPossition', async function (req, res) { // give someone admin or approver (only admins can use this)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    AdminAccountUsernames.set(packet.target, Cast.toBoolean(packet.admin));
    ApproverUsernames.set(packet.target, Cast.toBoolean(packet.approver));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": 'AppliedStatus' });
});
app.get('/api/users/getProfanityList', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const illegalWords = ProfanityChecker.getIllegalWords();
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(illegalWords);
});
app.post('/api/users/setProfanityList', async function (req, res) { // set the profanity list json
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const words = packet.json;
    if (typeof words !== 'object' || Array.isArray(words)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidData" });
        return;
    }
    // check for keys
    const keys = ["includingWords", "illegalWebsites", "spacedOutWordsOnly", "potentiallyUnsafeWords", "potentiallyUnsafeWordsSpacedOut"];
    for (const key of keys) {
        if (!Array.isArray(words[key])) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidData" });
            return;
        }
    }
    for (const newKey in words) {
        if (!keys.includes(newKey)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidData" });
            return;
        }
    }
    // send diff
    const illegalWords = ProfanityChecker.getIllegalWords();
    const diffText = ['```ansi'];
    for (const key of keys) {
        diffText.push(key);
        const newList = words[key];
        const oldList = illegalWords[key];
        for (const word of newList) {
            if (!oldList.includes(word)) {
                diffText.push(`\x1b[32;1m+ ${word}\x1b[0m`);
            }
        }
        for (const word of oldList) {
            if (!newList.includes(word)) {
                diffText.push(`\x1b[31;1m- ${word}\x1b[0m`);
            }
        }
    }
    diffText.push('```');
    ProfanityChecker.setIllegalWords(words);
    // send log
    const embedText = diffText.join('\n');
    const body = JSON.stringify({
        content: `${packet.user} updated filtering words`,
        embeds: [{
            title: `Filter Words changed by ${packet.user}`,
            color: 0x00c3ff,
            description: embedText,
            author: {
                name: String(packet.user).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.user).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(packet.user).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });
    // ok yea go successepic win
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.get('/api/errorAllProjectRequests', async function (req, res) { // set the state of allowing or preventing all project info getting requests (only admins can use this)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    GlobalRuntimeConfig.set("allowGetProjects", Cast.toBoolean(packet.enabled));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": 'AppliedStatus' });
});
app.get('/api/errorAllProjectUploads', async function (req, res) { // set the state of allowing or preventing all project uploading requests (only admins can use this)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.user))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    GlobalRuntimeConfig.set("allowUploadProjects", Cast.toBoolean(packet.enabled));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": 'AppliedStatus' });
});
let cachedStats = null;
let lastStatAccess = Date.now();
const tenMinutes = 10 * 60 * 1000
const cacheNewStats = async () => new Promise(resolve => {
    console.log('gathering data for site stats');
    os.cpuUsage((cpuUsage) => {
        const db = new Database(`${__dirname}/projects/published.json`);
        const userReports = UserManager.getAllReports();
        const reportDB = new Database(`./projectreports.json`);
        const userDB = new Database(`./userdata.json`);

        const projects = db.all();
        let all = projects.length;
        let inaccessible = 0;
        let unapproved = 0;
        let featured = 0;
        let remixes = 0;
        const users = [];
        for (const {data: project} of projects) {
            if (!users.includes(project.owner)) users.push(project.owner);
            if (!project.accepted) unapproved++;
            if (project.featured) featured++;
            if (project.remix) remixes++;
            if (!project.accepted || project.hidden) {
                inaccessible++;
            }
        }
        for (const username of Object.keys(userDB.data)) {
            if (!users.includes(username)) users.push(username);
        }

        console.log('caching site stats');
        lastStatAccess = Date.now();
        cachedStats = {
            all,
            inaccessible,
            unapproved,
            featured,
            remixes,
            reportedProjects: reportDB
                .all()
                .filter(rej => rej.exists).length,
            reportedUsers: userReports.length,
            users: users.length,
            admins: AdminAccountUsernames.all().length,
            mods: ApproverUsernames.all().length,
            new: true,
            nextRead: lastStatAccess + tenMinutes,
            freeMem: os.freemem(),
            totalMem: os.totalmem(),
            cpuUsage: cpuUsage * 100
        }
        console.log('finished caching site stats');
        resolve();
    });
});
// get counts on various site things
app.get('/api/projects/getSiteStats', async function (req, res) {
    // force updates to only happen every five minutes
    if (!cachedStats || Date.now() > lastStatAccess + tenMinutes) await cacheNewStats();

    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(cachedStats);
    cachedStats.new = false;
});
// returns who has perms
// made to ensure no one has perms they shouldnt have, limited to only mods and admins
app.get('/api/users/getSiteMods', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.user))
        && !ApproverUsernames.get(Cast.toString(packet.user))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "ThisAccountCannotAccessThisInformation" });
        return;
    }

    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json({
        admins: AdminAccountUsernames.all().filter(({data}) => data).map(({key}) => key),
        mods: ApproverUsernames.all().filter(({data}) => data).map(({key}) => key)
    });
});
// get approved projects
app.get('/api/projects/getApproved', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const db = new Database(`${__dirname}/projects/published.json`);
    // this is explained in paged api but basically just add normal projects to featured projects
    // because otherwise featured projects would come after normal projects
    const featuredProjects = [];
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted === true).filter(project => {
        if (project.featured) {
            featuredProjects.push(project);
        }
        return project.featured != true;
    });
    let returnArray = featuredProjects.concat(projects);
    if (Cast.toBoolean(req.query.reverse)) {
        returnArray = structuredClone(returnArray).reverse();
    }
    // make project list
    // new ProjectList() with .toJSON will automatically cut the pages for us
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
// get approved projects but only a certain amount
app.get('/api/projects/max', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    function grabArray() {
        const db = new Database(`${__dirname}/projects/published.json`)
        // this is explained in paged api but basically just add normal projects to featured projects
        // because otherwise featured projects would come after normal projects
        const featuredProjects = [];
        const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
            return sproject.date - project.date;
        }).filter(proj => proj.accepted === true).filter(project => {
            if (project.featured) {
                featuredProjects.push(project);
            }
            return project.featured != true;
        })
        if (String(req.query.featured) == "true") {
            return featuredProjects;
        }
        if (String(req.query.hidefeatured) == "true") {
            return projects;
        }
        const returnArray = featuredProjects.concat(projects);
        return returnArray;
    }
    let count = Number(req.query.amount);
    if (isNaN(count)) count = 0;
    if (!isFinite(count)) count = 0;
    if (count < 0) count = 0;
    if (count > 20) count = 20;
    count = Math.round(count);
    const arr = grabArray().slice(0, count);
    const projectsList = new ProjectList(arr);
    const returning = projectsList.toArray(false);
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
// get unapproved projects
app.get('/api/projects/getUnapproved', async function (req, res) {
    // 6/3/2023 unapproved projects are admin only
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.user, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.user))
        && !ApproverUsernames.get(Cast.toString(packet.user))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "ThisAccountCannotAccessThisInformation" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`)
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted === false);
    let returnArray = projects;
    if (Cast.toBoolean(req.query.reverse)) {
        returnArray = structuredClone(returnArray).reverse();
    }
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
// pm wrappers so that pm code doesnt need to be changed in a major way
app.get('/api/pmWrapper/projects', async function (req, res) { // add featured projects and normal projects together
    const db = new Database(`${__dirname}/projects/published.json`)
    // this is explained in paged api but basically just add normal projects to featured projects
    // because otherwise featured projects would come after normal projects
    const featuredProjects = []
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).map(project => {
        return { id: project.id, name: project.name, author: { username: project.owner }, accepted: project.accepted, featured: project.featured };
    }).filter(proj => proj.accepted === true).filter(project => {
        if (project.featured) {
            featuredProjects.push(project);
        }
        return project.featured != true;
    });
    const returnArray = featuredProjects.concat(projects);
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
app.get('/api/pmWrapper/remixes', async function (req, res) { // get remixes of a project
    const packet = req.query;
    if (!packet.id) {
        res.status(400);
        res.json({ "error": "IdNotSpecified" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    // we dont care about featured projects here because remixes cant be featured
    const json = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.remix == packet.id).filter(proj => proj.accepted === true);
    const projectsList = new ProjectList(json);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
app.get('/api/pmWrapper/iconUrl', async function (req, res) { // get icon url of a project
    if (!req.query.id) {
        res.status(400);
        res.json({ "error": "IdNotSpecified" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    const json = db.get(String(req.query.id));
    if (!json) {
        res.status(400);
        res.json({ "error": "IdNotValid" });
        return;
    }
    fs.readFile(`./projects/uploadedImages/p${json.id}.png`, (err, buffer) => {
        if (err) {
            res.status(404);
            res.json({
                "error": "ImageNotFoundOrErrorOccurred",
                "realerror": String(err)
            });
            return;
        }
        jimp.read(buffer).then(async image => {
            const width = Cast.toBoolean(req.query.widescreen) ? 640 : 480;
            image.cover(width / 2, 360 / 2, async (err, image) => {
                if (err) {
                    res.status(500);
                    res.json({
                        "error": "CompressionCroppingError",
                        "realerror": String(err)
                    });
                    return;
                }
                const buffer = await image.getBufferAsync(jimp.MIME_JPEG);
                res.status(200);
                res.contentType(jimp.MIME_JPEG);
                res.send(buffer);
            });
        }).catch(err => {
            res.status(500);
            res.json({
                "error": "CompressionError",
                "realerror": String(err)
            });
            return;
        });
    });
});
app.get('/api/pmWrapper/getProject', async function (req, res) { // get data of a(n approved) project
    if (!req.query.id) {
        res.status(400);
        res.json({ "error": "IdNotSpecified" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    const json = db.get(String(req.query.id));
    if (!json) {
        res.status(400);
        res.json({ "error": "IdNotValid" });
        return;
    }
    res.status(200);
    res.json({ id: json.id, name: json.name, author: { id: -1, username: json.owner, } });
});
// scratch auth implementation
const generateErrorCode = (worked, verifyErr, valid, validRedir, redirect, local) => {
    if (typeof verifyErr === 'object') {
        try {
            verifyErr = JSON.stringify(verifyErr);
        } catch { // happens if we get recursion
            verifyErr = '{}';
        }
    }
    
    const text = [];
    text.push(worked ? 'CanVerify: true' : 'CanVerify: false');
    text.push(valid ? 'ValidCode: true' : 'ValidCode: false');
    text.push(validRedir ? 'ValidRedirect: true' : 'ValidRedirect: false');
    text.push(local ? 'Local: true' : 'Local: false');
    text.push('Redirect: ' + (redirect ? redirect : 'NO_REDIRECT'));
    text.push('VerifyError: ' + (verifyErr ? verifyErr : 'NO_VERIFY_ERR'));
    return text
        .map(escapeXML) // sanitize for HTML
        .map(text => text // sanitize for JS
            .replaceAll('\\', '\\\\')
            .replaceAll('`', '\\`')
            .replaceAll('${', '$\\{')
            .replaceAll('@', ' @ ') // remember, they'll be sending these in discord!
        )
        .join('<br>');
};
const failedLoginHTML = fs.readFileSync("./failed_login.html", "utf8");
const handleLogin = (req, res, local) => {
    const privateCode = Cast.toString(req.query.privateCode);
    const expectingJSON = Cast.toString(req.header("Content-Type")).endsWith('json');
    UserManager.verifyCode(privateCode).then(response => {
        // check if it is a malicious site
        // note: malicious sites cannot read the private code in the URL if it is the right redirect
        //       thank you cors, you finally did something useful

        // malicious APPS could, but at that point your just :trollface:d so :idk_man:
        const invalidRedirect = local ? (
            response.redirect !== 'https://projects.penguinmod.com/api/users/loginLocal'
            && response.redirect !== 'http://localhost:8080/api/users/loginLocal'
        ) : (
            response.redirect !== 'https://projects.penguinmod.com/api/users/login'
        );
        if ((!response.valid) || (invalidRedirect)) {
            const errorCode = generateErrorCode(true, null, response.valid, !invalidRedirect, response.redirect, local);
            res.status(400);
            if (expectingJSON) {
                res.header("Content-Type", 'application/json');
                res.json({ "error": "InvalidLogin", "code": errorCode });
            } else {
                res.header("Content-Type", 'text/html');
                res.send(failedLoginHTML.replace('{{ERROR_CODE}}', errorCode));
            }
            if (invalidRedirect) {
                console.log(response.redirect, "tried to falsely authenticate", response.username);
            }
            return;
        }
        // todo: maybe we should clear the login after a couple days or so?
        const username = response.username;
        UserManager.setCode(username, privateCode);
        if (!UserManager.getProperty(username, "firstLogin")) {
            UserManager.setProperty(username, "firstLogin", Date.now());
        }
        UserManager.setProperty(username, "latestLogin", Date.now());
        const userIP = req.ip;
        if (userIP) {
            // easier if the IP is the key
            UsernameIP.set(Buffer.from(Cast.toString(userIP), 'utf8').toString('hex'), username);
        }
        // close window by opening success.html
        res.header("Content-Type", 'text/html');
        res.status(200);
        res.sendFile(path.join(__dirname, 
            local ? "./success_local.html" : "./success.html"
        ));
    }).catch((err) => {
        const errorCode = generateErrorCode(false, err, false, false, null, local);
        res.status(400);
        if (expectingJSON) {
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidLogin", "code": errorCode });
        } else {
            res.header("Content-Type", 'text/html');
            res.send(failedLoginHTML.replace('{{ERROR_CODE}}', errorCode));
        }
    });
};
app.get('/api/users/login', async function (req, res) { // login with scratch
    handleLogin(req, res, false);
});
app.get('/api/users/loginLocal', async function (req, res) { // login with local account (like localhost)
    handleLogin(req, res, true);
});
// logout
app.get('/api/users/logout', (req, res) => { // logout
    if (!UserManager.isCorrectCode(req.query.user, req.query.code)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidLogin" });
        return;
    }
    UserManager.logoutUser(req.query.user);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": "LoginIsNowInvalidated" });
});
app.get('/api/users/usernameFromCode', async function (req, res) { // get username from private code
    const privateCode = Cast.toString(req.query.privateCode);
    const username = UserManager.usernameFromCode(privateCode);
    if (username == null) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CodeNotFound" });
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(GenerateProfileJSON(Cast.toString(username)));
});
// extra stuff
app.get('/api/users/isAdmin', async function (req, res) { // check if user is admin (by username)
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "admin": AdminAccountUsernames.get(Cast.toString(req.query.username)) });
});
app.get('/api/users/isApprover', async function (req, res) { // check if user is approver (by username)
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        "approver": ApproverUsernames.get(Cast.toString(req.query.username))
            || AdminAccountUsernames.get(Cast.toString(req.query.username))
    });
});
app.get('/api/users/getMyProjects', async function (req, res) { // get projects of a user (need username and private code)
    if (!UserManager.isCorrectCode(req.query.user, req.query.code)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    const projects = db.all().map(data => data.data).filter(project => project.owner === req.query.user);

    let result = projects;

    if (String(req.query.sorted) === "true") {
        result.sort((project, sproject) => {
            return sproject.date - project.date
        });
        const featuredProjects = [];
        const waitingProjects = [];
        const hiddenProjects = [];
        result = result.filter(project => {
            if (project.featured) {
                featuredProjects.push(project);
                return false;
            }
            if (!project.accepted) {
                waitingProjects.push(project);
                return false;
            }
            if (project.hidden) {
                hiddenProjects.push(project);
                return false;
            }
            return true;
        })
        const returnArray = featuredProjects.concat(result, waitingProjects, hiddenProjects);
        result = returnArray;
    }

    // paginate
    const projectsList = new ProjectList(result);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.status(200)
    res.header("Content-Type", 'application/json');
    res.json(returning)
});

// MESSAGES
app.get('/api/users/getMessages', async function (req, res) { // get a users messages (you have to be the user) (by username and private code)
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getMessages(packet.username);
    const messageList = new GenericList(messages);
    const returning = messageList.toJSON(true, Cast.toNumber(req.query.page));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(returning);
});
// nvm, endpoint reused for "guidelines" messages
app.post('/api/users/addMessage', async function (req, res) { // add a message to a user (by username and private code)
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    // validate message (do we have perms? is this a valid message?)
    const unsafeMessage = packet.message;
    const invalidate = () => {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidMessage" });
    };
    const notallowed = () => {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CannotSendThisMessageType" });
    };

    // is this actually a message object?
    if (typeof unsafeMessage !== "object") return invalidate();
    if (Array.isArray(unsafeMessage)) return invalidate();

    // is the type of this message actually decided?
    if (typeof unsafeMessage.type !== "string") return invalidate();

    // check message type & add it
    const username = Cast.toString(packet.username);
    const target = packet.target;
    switch (unsafeMessage.type) {
        case 'custom':
            if (!AdminAccountUsernames.get(username)) return notallowed();
            if (typeof unsafeMessage.text !== "string") return invalidate();
            UserManager.addMessage(target, {
                type: unsafeMessage.type,
                text: unsafeMessage.text
            });
            break;
        case 'guidelines':
            if (!AdminAccountUsernames.get(username)) return notallowed();
            if (typeof unsafeMessage.section !== "string") return invalidate();
            const db = new Database(`./userdata.json`);
            const usernames = db.all().map(item => item.key);
            // use addMessage locally (see the last arg being true)
            for (const username of usernames) {
                UserManager.addMessage(username, {
                    type: unsafeMessage.type,
                    section: unsafeMessage.section
                }, true);
            }
            // save local changes to the file
            UserManager.applyMessages();
            break;
        default:
            return invalidate();
    }

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.get('/api/users/getMessageCount', async function (req, res) { // get a users message count (you have to be the user) (by username and private code)
    const packet = req.query;
    if (!UserManager.isCorrectCode(Cast.toString(packet.username), packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getUnreadMessages(Cast.toString(packet.username));
    res.status(200);
    res.header("Content-Type", 'text/plain');
    res.send(String(messages.length));
});
app.post('/api/users/markMessagesAsRead', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (packet.id) {
        UserManager.modifyMessage(packet.username, packet.id, (message) => ({
            ...message,
            read: true
        }));
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json({ "success": true });
        return;
    }
    if (packet.ids) {
        if (!Array.isArray(packet.ids)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "IDsMustBeArray" });
            return;
        }
        for (const id of packet.ids) {
            UserManager.modifyMessage(packet.username, id, (message) => ({
                ...message,
                read: true
            }));
        }
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json({ "success": true });
        return;
    }
    UserManager.markMessagesAsRead(packet.username);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// BADGES
app.get('/api/users/getBadges', async function (req, res) { // get a users badges (by username)
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!packet.username) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameNotSpecified" });
        return;
    }
    const badges = UserManager.getProperty(packet.username, "badges");
    if (!Array.isArray(badges)) {
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json([]);
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(badges);
});
app.post('/api/users/setBadges', async function (req, res) { // set a users badges (you must be an admin) (by username)
    const packet = req.body;
    if (!UserManager.isCorrectCode(Cast.toString(packet.username), packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const newBadges = packet.badges;
    const target = packet.target;
    if (typeof target !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetMustBeString" });
        return;
    }
    if (!target) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetNotSpecified" });
        return;
    }
    if (!Array.isArray(newBadges)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BadgesMustBeArray" });
        return;
    }
    UserManager.setProperty(target, "badges", newBadges);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        success: true,
        newbadges: UserManager.getProperty(target, "badges")
    });
});

// MyFeaturedProject
// sets a project for a user to display on their profile
app.post('/api/users/setMyFeaturedProject', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (UserManager.isBanned(packet.username)) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    if (typeof packet.id !== 'number') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IDNotSpecified" });
        return;
    }
    if (packet.id < 0) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidID" });
        return;
    }
    if (typeof packet.title !== 'number') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TitleNotSpecified" });
        return;
    }
    if (packet.title < 0 || packet.title > 500) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidTitleType" });
        return;
    }
    UserManager.setProperty(packet.username, "myFeaturedProject", Math.round(packet.id));
    UserManager.setProperty(packet.username, "myFeaturedProjectTitle", Math.round(packet.title));

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// About Me
// sets text for a user to display on their profile
app.post('/api/users/setBio', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (UserManager.isBanned(packet.username)) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    if (typeof packet.bio !== 'string') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidBioInput" });
        return;
    }
    if (packet.bio.length > 2048) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BioLengthMustBeLessThan2048Chars" });
        return;
    }
    if (ProfanityChecker.containsUnsafeContent(packet.bio)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        ProfanityChecker.sendHeatLog(packet.bio, "profileBio", packet.username);
        return;
    }
    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(packet.bio, "profileBio", packet.username);
    UserManager.setProperty(packet.username, "profileBio", packet.bio);

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// (ADMIN) sets text for another user to display on their profile
app.post('/api/users/setUserBioAdmin', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    if (!packet.target || typeof packet.target !== 'string') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidTarget" });
        return;
    }
    if (typeof packet.bio !== 'string') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidBioInput" });
        return;
    }
    if (packet.bio.length > 2048) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BioLengthMustBeLessThan2048Chars" });
        return;
    }
    UserManager.setProperty(packet.target, "profileBio", packet.bio);
    const body = JSON.stringify({
        content: `${packet.target}'s bio was edited by ${packet.username}`,
        embeds: [{
            title: `${packet.target} had their bio edited`,
            color: 0xff0000,
            description: packet.bio,
            fields: [
                {
                    name: "Edited by",
                    value: `${packet.username}`
                },
                {
                    name: "URL",
                    value: `https://penguinmod.com/profile?user=${packet.target}`
                },
            ],
            author: {
                name: String(packet.target).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.target).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(packet.target).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// following
app.get('/api/users/getFollowerCount', async function (req, res) { // get a users follower count (by username)
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!packet.username) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameNotSpecified" });
        return;
    }
    const followers = UserManager.getFollowers(packet.username);
    if (!Array.isArray(followers)) {
        res.status(200);
        res.header("Content-Type", 'text/plain');
        res.send("0");
        return;
    }
    res.status(200);
    res.header("Content-Type", 'text/plain');
    res.send(Cast.toString(followers.length));
});
app.get('/api/users/isFollowing', async function (req, res) { // check if a user is following another user (by username)
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!packet.target) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetNotSpecified" });
        return;
    }
    const followers = UserManager.getFollowers(packet.target);
    if (!Array.isArray(followers)) {
        res.status(200);
        res.header("Content-Type", 'application/json');
        res.json({
            following: false,
            count: 0
        });
        return;
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        following: followers.includes(packet.username),
        count: followers.length
    });
});
app.post('/api/users/followToggle', async function (req, res) {
    const packet = req.body;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!packet.target) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TargetNotSpecified" });
        return;
    }
    const followers = UserManager.getFollowers(packet.target) ?? [];
    let isNowFollowing = true;
    if (followers.includes(packet.username)) {
        isNowFollowing = false;
        UserManager.removeFollower(packet.target, packet.username);
    } else {
        UserManager.addFollower(packet.target, packet.username);
    }
    if (isNowFollowing && !UserManager.getHadFollowers(packet.target).includes(packet.username)) {
        UserManager.addMessage(packet.target, {
            type: "followerAdded",
            name: `${packet.username}`
        });
        UserManager.addToUserFeed(packet.target, {
            type: "follow",
            username: packet.username
        });
    }
    // check if we can get followers badge
    if (UserManager.getFollowers(packet.target).length >= 50) {
        const badge = "followers";
        const newBadges = UserManager.getProperty(packet.target, "badges") ?? [];
        if (!newBadges.includes(badge)) {
            newBadges.push(badge);
            UserManager.setProperty(packet.target, "badges", newBadges);
            UserManager.addMessage(packet.target, {
                type: "newBadge",
                name: badge
            });
        }
    }
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        following: isNowFollowing,
        count: (UserManager.getFollowers(packet.target) ?? []).length
    });
});

// FEED
app.get('/api/users/getMyFeed', async function (req, res) {
    const packet = req.query;
    if (typeof packet.username !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UsernameMustBeString" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const feed = UserManager.getUserFeed(packet.username);
    const messageList = new GenericList(feed);
    const returning = messageList.toJSON(true, Cast.toNumber(req.query.page ?? 0));
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(returning);
});

// banning
app.post('/api/users/ban', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BanReasonIsRequired" });
        return;
    }
    if (packet.reason.length < 10) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "BanReasonIsLessThan10Chars" });
        return;
    }

    const bannedUser = Cast.toString(packet.target);
    const bannedReason = Cast.toString(packet.reason);

    // ban
    UserManager.ban(bannedUser, bannedReason);
    // add message
    UserManager.addModeratorMessage(bannedUser, {
        type: "ban",
        reason: packet.reason,
        disputable: true
    });

    // post log
    const body = JSON.stringify({
        content: `${bannedUser} was banned by ${packet.username}`,
        embeds: [{
            title: `${bannedUser} was banned`,
            color: 0xff0000,
            fields: [
                {
                    name: "Banned by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${bannedReason}`
                }
            ],
            author: {
                name: String(bannedUser).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(bannedUser).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(bannedUser).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) {
            res.status(200);
            res.header("Content-Type", 'application/json');
            res.json({ "success": true });
        } else {
            res.status(500);
            res.header('Content-Type', 'application/json')
            res.json({ error: 'LogFailed' })
        }
    });
});
app.post('/api/users/unban', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "UnbanReasonIsRequired" });
        return;
    }

    const bannedUser = Cast.toString(packet.target);
    const bannedReason = Cast.toString(packet.reason);

    // unban
    UserManager.unban(bannedUser);
    // add message
    UserManager.addModeratorMessage(bannedUser, {
        type: "unban",
        reason: packet.reason,
        disputable: false // why would you dispute an unban? lmfao
    });

    // post log
    const body = JSON.stringify({
        content: `${bannedUser} was unbanned by ${packet.username}`,
        embeds: [{
            title: `${bannedUser} was unbanned`,
            color: 0x00ff00,
            fields: [
                {
                    name: "Unbanned by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${bannedReason}`
                }
            ],
            author: {
                name: String(bannedUser).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(bannedUser).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(bannedUser).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) {
            res.status(200);
            res.header("Content-Type", 'application/json');
            res.json({ "success": true });
        } else {
            res.status(500);
            res.header('Content-Type', 'application/json')
            res.json({ error: 'LogFailed' })
        }
    });
});

// REPORTING
// users
app.get('/api/users/report', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reportedUser = Cast.toString(packet.target);
    const reportedReason = Cast.toString(packet.reason).substring(0, 2048);

    globalOperationCounter++;
    const id = `repu-${Date.now()}-${globalOperationCounter}`;
    UserManager.addReport(reportedUser, {
        reason: reportedReason,
        reporter: packet.username,
        id
    }, true);

    const body = JSON.stringify({
        content: `${reportedUser} was reported by ${packet.username}`,
        embeds: [{
            title: `${reportedUser} was reported`,
            color: 0xff0000,
            fields: [
                {
                    name: "Reported by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${reportedReason}`
                },
                {
                    name: "URL",
                    value: `https://penguinmod.com/profile?user=${reportedUser}`
                }
            ],
            author: {
                name: String(reportedUser).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(reportedUser).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(reportedUser).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.get('/api/users/getReports', async function (req, res) {
    const packet = req.query;
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reports = UserManager.getReports(Cast.toString(packet.target));
    const mergedReports = new ReportList(reports).toMerged();
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(mergedReports);
});
app.get('/api/users/getContentWithReports', async function (req, res) {
    const packet = req.query;
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reports = UserManager.getAllReports();
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(reports
        .sort((user, suser) => suser.data.length - user.data.length)
        .map(r => ({
            username: r.key,
            reports: r.data.length
        })));
});
app.post('/api/users/deleteReports', async function (req, res) {
    const packet = req.body;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }
    if (typeof packet.target !== "string") {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoTargetSpecified" });
        return;
    }

    const reportDB = new Database(`./userreports.json`);
    const reportedUsername = Cast.toString(packet.id);
    if (!reportDB.has(reportedUsername)) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoUserReportsFound" });
        return;
    }
    const reports = reportDB.get(reportedUsername);
    const newReports = reports.filter(report => report.reporter !== packet.target);
    if (newReports.length <= 0) {
        reportDB.delete(reportedUsername);
    } else {
        reportDB.set(reportedUsername, newReports);
    }

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json({ success: true });
});
// projects
app.get('/api/projects/report', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reportedProject = Cast.toString(packet.target);
    const reportedReason = Cast.toString(packet.reason).substring(0, 2048);

    const db = new Database(`${__dirname}/projects/published.json`);
    const project = db.get(reportedProject);
    if (!project) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NotFound" });
        return;
    }

    const reportDB = new Database(`./projectreports.json`);
    let projectReports = reportDB.get(reportedProject);
    if (!Array.isArray(projectReports)) projectReports = [];

    globalOperationCounter++;
    const id = `rep-${Date.now()}-${globalOperationCounter}`;
    projectReports.push({ reason: reportedReason, reporter: packet.username, id });
    reportDB.set(reportedProject, projectReports);
    UserManager.punishSameUserReports(projectReports, packet.username, `Project ${reportedProject}`);

    const body = JSON.stringify({
        content: `Project ${reportedProject} was reported by ${packet.username}`,
        embeds: [{
            title: `Project ${reportedProject} was reported`,
            color: 0xff0000,
            fields: [
                {
                    name: "Reported by",
                    value: `${packet.username}`
                },
                {
                    name: "Reason",
                    value: `${reportedReason}`
                },
                {
                    name: "URL",
                    value: `https://projects.penguinmod.com/${reportedProject}`
                }
            ],
            author: {
                name: String(packet.username).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.username).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json({ success: true });
});
app.get('/api/projects/getReports', async function (req, res) {
    const packet = req.query;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }
    const projectId = Cast.toString(packet.target);

    const db = new Database(`${__dirname}/projects/published.json`);
    const project = db.get(projectId);
    if (!project) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NotFound" });
        return;
    }

    const reportDB = new Database(`./projectreports.json`);
    let projectReports = reportDB.get(projectId);
    if (!Array.isArray(projectReports)) projectReports = [];
    const mergedReports = new ReportList(projectReports).toMerged();

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json(mergedReports);
});
app.get('/api/projects/getContentWithReports', async function (req, res) {
    const packet = req.query;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }

    const reportDB = new Database(`./projectreports.json`);
    const allReports = reportDB.all();
    const projectDB = new Database(`${__dirname}/projects/published.json`);

    const properFormattedReports = allReports
        .sort((project, sproject) => sproject.data.length - project.data.length)
        .map(r => ({
            id: r.key,
            reports: r.data.length
        }));
    for (const content of properFormattedReports) {
        const project = projectDB.get(content.id);
        if (project) {
            content.exists = true;
            content.author = project.owner;
            content.name = project.name;
        } else {
            content.exists = false;
        }
    }

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json(properFormattedReports);
});
app.post('/api/projects/deleteReports', async function (req, res) {
    const packet = req.body;
    if (!AdminAccountUsernames.get(Cast.toString(packet.username))
        && !ApproverUsernames.get(Cast.toString(packet.username))) {
        res.status(403);
        res.header("Content-Type", "application/json");
        res.json({ error: "FeatureDisabledForThisAccount" });
        return;
    }
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "Reauthenticate" });
        return;
    }
    if (typeof packet.target !== "string") {
        res.status(400);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoTargetSpecified" });
        return;
    }

    const reportDB = new Database(`./projectreports.json`);
    const projectId = Cast.toString(packet.id);
    if (!reportDB.has(projectId)) {
        res.status(404);
        res.header("Content-Type", "application/json");
        res.json({ error: "NoProjectFound" });
        return;
    }
    const reports = reportDB.get(projectId);
    const newReports = reports.filter(report => report.reporter !== packet.target);
    if (newReports.length <= 0) {
        reportDB.delete(projectId);
    } else {
        reportDB.set(projectId, newReports);
    }

    res.status(200);
    res.header("Content-Type", "application/json");
    res.json({ success: true });
});

// DISPUTE
app.post('/api/users/dispute', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getMessages(packet.username);
    const message = messages.filter(message => message.id === packet.id)[0];
    if (!message) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    if (!message.disputable) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MessageNotDisputable" });
        return;
    }

    // post log
    const body = JSON.stringify({
        content: `${packet.username} replied to moderator message`,
        embeds: [{
            title: `Reply by ${packet.username}`,
            color: 0xff8800,
            fields: [
                {
                    name: "Message Replied to",
                    value: `${message.reason ? message.reason : ''}\n\n\`\`${message.type} (${message.id})\`\``
                },
                {
                    name: "Project ID (if applicable)",
                    value: `${message.projectData ? message.projectData.id : '(not applicable)'}`
                },
                {
                    name: "Reply",
                    value: `${packet.text}`
                }
            ],
            author: {
                name: String(packet.username).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.username).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    }).then(log => {
        if (log.ok) {
            UserManager.modifyMessage(packet.username, packet.id, message => {
                message.disputable = false;
                message.dispute = packet.text ?? ''
                return message;
            });

            res.status(200);
            res.header("Content-Type", 'application/json');
            res.json({ "success": true });
        } else {
            res.status(500);
            res.header('Content-Type', 'application/json')
            res.json({ error: 'LogFailed' })
        }
    });
});
app.post('/api/users/disputeRespond', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const messages = UserManager.getMessages(packet.username);
    const message = messages.filter(message => message.id === packet.id)[0];
    if (!message) {
        res.status(404);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    if (!message.type === 'reject') {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MessageNotDisputable" });
        return;
    }

    // add message
    UserManager.addModeratorMessage(packet.username, {
        disputeId: String(packet.id),
        type: "disputeResponse",
        reason: packet.reason,
        disputable: true
    });

    // post log
    const body = JSON.stringify({
        content: `${packet.approver} responded to reply from ${packet.username}`,
        embeds: [{
            title: `${packet.approver} responded to a reply`,
            color: 0x6600ff,
            fields: [
                {
                    name: "Message ID",
                    value: `${message.id}`
                },
                {
                    name: "Original Reply",
                    value: `${message.dispute ? message.dispute : '(reply is too old, search message ID in logs)'}`
                },
                {
                    name: "Moderator Reply",
                    value: `${packet.reason}`
                }
            ],
            author: {
                name: String(packet.username).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.username).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// approve uploaded projects
app.get('/api/projects/approve', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(packet.id)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }

    // newMeta
    // replace
    let isUpdated = false;
    let isRemix = false;

    let idToSetTo = packet.id;
    // idk if db uses a reference to the object or not
    const project = structuredClone(db.get(Cast.toString(packet.id)));
    if (project.updating) {
        isUpdated = true;
    }
    project.updating = false;
    project.accepted = true;
    if (Cast.toBoolean(project.remix)) isRemix = true;
    db.set(String(idToSetTo), project);

    UserManager.notifyFollowers(project.owner, {
        type: "upload",
        username: project.owner,
        content: {
            id: project.id,
            name: project.name
        }
    });
    if (isRemix) {
        if (db.has(String(project.remix))) {
            const remixedProject = db.get(String(project.remix));
            UserManager.addMessage(remixedProject.owner, {
                type: "remix",
                projectId: remixedProject.id,
                name: `${remixedProject.name}`, // included for less API calls
                remixId: project.id,
                remixName: project.name,
            });
            UserManager.addToUserFeed(remixedProject.owner, {
                type: "remixed",
                username: remixedProject.owner,
                content: {
                    id: remixedProject.id,
                    name: remixedProject.name
                }
            });
        }
    }
    {
        // post log
        const projectImage = String(`https://projects.penguinmod.com/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
        const body = JSON.stringify({
            content: `"${project.name}" was approved by ${packet.approver}`,
            embeds: [{
                title: `${project.name} was approved`,
                color: 0x00ff00,
                image: { url: projectImage },
                url: "https://studio.penguinmod.com/#" + project.id,
                fields: [
                    {
                        name: "Approved by",
                        value: `${packet.approver}`
                    }
                ],
                author: {
                    name: String(project.owner).substring(0, 50),
                    icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                    url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
                },
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.ApproverLogWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body
        });
    }

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
    if (Cast.toBoolean(req.query.webhook) === false) return;
    const projectImage = String(`https://projects.penguinmod.com/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
    const body = JSON.stringify({
        content: `A project was ${isUpdated ? "updated" : (isRemix ? "remixed" : "approved")}!`,
        embeds: [{
            title: String(project.name).substring(0, 250),
            description: String(project.instructions + "\n\n" + project.notes).substring(0, 2040),
            image: { url: projectImage },
            color: (isUpdated ? 14567657 : (isRemix ? 6618880 : 41440)),
            url: String("https://studio.penguinmod.com/#" + String(project.id)),
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
            }
        }]
    });
    fetch(process.env.DiscordWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });
    // .then(res => res.text().then(t => console.log("WebhookResponse",res.status,t))).catch(err => console.log("FailedWebhookSend", err))
});
// reject projects
app.post('/api/projects/reject', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    if (typeof packet.reason !== "string") {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "RejectionReasonIsRequired" });
        return;
    }
    if (packet.reason.length < 10) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "RejectionReasonIsLessThan10Chars" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(String(packet.id))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(packet.id));
    // if (project.accepted) {
    //     res.status(403);
    //     res.header("Content-Type", 'application/json');
    //     res.json({ "error": "CannotRejectApprovedProject" });
    //     return;
    // }
    // post log
    const body = JSON.stringify({
        content: `"${project.name}" was removed by ${packet.approver}`,
        embeds: [{
            title: `${project.name} was removed`,
            color: 0xff0000,
            fields: [
                {
                    name: "Removed by",
                    value: `${packet.approver}`
                },
                {
                    name: "Project ID",
                    value: `${project.id}`
                },
                {
                    name: "Reason",
                    value: `${packet.reason}`
                }
            ],
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });
    // add message
    UserManager.addModeratorMessage(project.owner, {
        projectId: String(packet.id),
        type: "reject",
        name: `${project.name}`, // included for less API calls
        reason: packet.reason,
        projectData: project,
        disputable: true
    });
    db.delete(String(packet.id));
    const projectFilePath = `./projects/uploaded/p${packet.id}.pmp`;
    const projectImagePath = `./projects/uploadedImages/p${packet.id}.png`;
    const backupProjectMetaPath = `./projects/backup/proj${packet.id}.json`;
    fs.writeFile(backupProjectMetaPath, JSON.stringify(project, null, 4), 'utf8', (err) => {
        if (err) return console.log('failed to backup project meta for', packet.id);
    });
    fs.readFile(projectFilePath, (err, data) => {
        if (err) return console.log('failed to open project file for', packet.id, ', will not be deleted from rejection');
        fs.writeFile(`./projects/backup/proj${packet.id}.pmp`, data, (err) => {
            if (err) return console.log('failed to backup project file for', packet.id, ', will not be deleted from rejection');
            fs.unlink(projectFilePath, err => {
                if (err) console.log("failed to delete project data for", packet.id, ";", err);
            });
        });
    });
    fs.readFile(projectImagePath, (err, data) => {
        if (err) return console.log('failed to open image for', packet.id, ', will not be deleted from rejection');
        fs.writeFile(`./projects/backup/proj${packet.id}.png`, data, (err) => {
            if (err) return console.log('failed to backup project image for', packet.id, ', will not be deleted from rejection');
            fs.unlink(projectImagePath, err => {
                if (err) console.log("failed to delete project image for", packet.id, ";", err);
            });
        });
    });
    console.log(packet.approver, "rejected", packet.id);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// RELATED TO ALREADY REJECTED PROJECTS
app.get('/api/projects/downloadRejected', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        const allowed = await new Promise((resolve) => {
            const backupProjectMetaPath = `./projects/backup/proj${packet.id}.json`;
            fs.readFile(backupProjectMetaPath, 'utf8', (err, data) => {
                if (err) {
                    // this was rejected so long ago that we really dont care that anyone can download it
                    return resolve(true);
                }
                const projectMeta = SafeJSONParse(data);
                resolve(projectMeta.owner === packet.approver);
            });
        });
        if (!allowed) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    const projectDataPath = `./projects/backup/proj${packet.id}.pmp`;
    fs.readFile(projectDataPath, (err) => {
        if (err) {
            res.status(404);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "ProjectNotFound" });
            return;
        }
        res.status(200);
        res.sendFile(path.join(__dirname, projectDataPath));
    });
});
app.post('/api/projects/restoreRejected', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    // attempt to restore
    const db = new Database(`${__dirname}/projects/published.json`);
    const projectId = packet.id;

    const backupProjectFilePath = `./projects/backup/proj${projectId}.pmp`;
    const backupProjectImagePath = `./projects/backup/proj${projectId}.png`;
    const backupProjectMetaPath = `./projects/backup/proj${projectId}.json`;

    const restoredProjectFilePath = `./projects/uploaded/p${projectId}.pmp`;
    const restoredProjectImagePath = `./projects/uploadedImages/p${projectId}.png`;
    // PROJECT FILE
    fs.readFile(backupProjectFilePath, (err, data) => {
        if (err) {
            console.warn('couldnt restore file for', projectId, err);
            return;
        }
        fs.writeFile(restoredProjectFilePath, data, (err) => {
            if (err) {
                console.warn('couldnt restore file for', projectId, err);
                return;
            }
        })
    });
    // PROJECT IMAGE
    fs.readFile(backupProjectImagePath, (err, data) => {
        if (err) {
            console.warn('couldnt restore image for', projectId, err);
            return;
        }
        fs.writeFile(restoredProjectImagePath, data, (err) => {
            if (err) {
                console.warn('couldnt restore image for', projectId, err);
                return;
            }
        })
    });
    // PROJECT META
    fs.readFile(backupProjectMetaPath, 'utf8', (err, data) => {
        if (err) {
            // search userMessages instead
            let projectMetadata = {
                "id": projectId,
                "name": "Unknown Project " + projectId,
                "instructions": "",
                "notes": "This project was restored, but it's information was missing or corrupted.\nPlease edit the project to restore this information.",
                "owner": packet.approver, // we dont know the owner
                "featured": false,
                "accepted": true,
                "date": Date.now(),
                "views": 0,
                "loves": [],
                "votes": [],
                "updating": false
            };
            const messageData = UserManager.getRawMessageData();
            for (const username in messageData) {
                for (const message of messageData[username]) {
                    if (message.type === 'reject' && message.projectData) {
                        if (message.projectData.id === projectId) {
                            projectMetadata = message.projectData;
                            break;
                        }
                    }
                }
            }
            const usingData = {
                ...projectMetadata,
                accepted: true,
                featured: false
            }
            if (usingData.owner) {
                UserManager.addModeratorMessage(usingData.owner, {
                    type: "restored",
                    projectId,
                    name: `${usingData.name}` // included for less API calls
                });
            }
            db.set(Cast.toString(projectId), usingData);
            return;
        }
        let projectMeta;
        try {
            projectMeta = JSON.parse(data);
        } catch (err) {
            console.warn('couldnt restore metadata for', projectId, err);
            return;
        }
        const usingData = {
            ...projectMeta,
            accepted: true,
            featured: false
        }
        if (usingData.owner) {
            UserManager.addModeratorMessage(usingData.owner, {
                type: "restored",
                projectId,
                name: `${usingData.name}` // included for less API calls
            });
        }
        db.set(Cast.toString(projectId), usingData);
    });

    // valid info
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.post('/api/projects/deleteRejected', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (
        !AdminAccountUsernames.get(Cast.toString(packet.approver))
        // && !ApproverUsernames.get(Cast.toString(packet.approver))
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    // attempt to delete
    const projectId = packet.id;

    const backupProjectFilePath = `./projects/backup/proj${projectId}.pmp`;
    const backupProjectImagePath = `./projects/backup/proj${projectId}.png`;
    const backupProjectMetaPath = `./projects/backup/proj${projectId}.json`;
    // PROJECT FILE
    fs.unlink(backupProjectFilePath, (err) => {
        if (err) {
            console.warn('couldnt delete file for', projectId, err);
            return;
        }
    });
    // PROJECT IMAGE
    fs.unlink(backupProjectImagePath, (err) => {
        if (err) {
            console.warn('couldnt delete image for', projectId, err);
            return;
        }
    });
    // PROJECT META
    fs.unlink(backupProjectMetaPath, (err) => {
        if (err) {
            console.warn('couldnt delete metadata for', projectId, err);
            return;
        }
    });

    // valid info
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});

// feature uploaded projects
app.get('/api/projects/feature', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (!AdminAccountUsernames.get(Cast.toString(packet.approver))) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }
    const idToSetTo = String(packet.id);
    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(idToSetTo)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    // idk if db uses a reference to the object or not
    const project = structuredClone(db.get(idToSetTo));
    if (!project.accepted) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CantFeatureUnapprovedProject" });
        return;
    }
    // if (project.votes.length < 6) {
    //     res.status(400);
    //     res.header("Content-Type", 'application/json');
    //     res.json({ "error": "CantFeatureProjectWithLessThan6Votes" });
    //     return;
    // }
    project.featured = true;
    db.set(String(idToSetTo), project);
    UserManager.addMessage(project.owner, {
        type: "featured",
        projectId: idToSetTo,
        name: `${project.name}` // included for less API calls
    });
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
    if (Cast.toBoolean(req.query.webhook) === false) return;
    const projectImage = String(`https://projects.penguinmod.com/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
    const projectTitle = String(project.name).substring(0, 250);
    const body = JSON.stringify({
        content: `⭐ **${projectTitle}** was **featured**! ⭐`,
        embeds: [{
            title: projectTitle,
            image: { url: projectImage },
            color: 16771677,
            url: String("https://studio.penguinmod.com/#" + String(project.id)),
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
            }
        }]
    });
    fetch(process.env.DiscordWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
    });
    // .then(res => res.text().then(t => console.log("WebhookResponse",res.status,t))).catch(err => console.log("FailedWebhookSend", err))
});
// toggle liking or voting for uploaded projects
app.post('/api/projects/toggleProjectVote', async function (req, res) {
    const packet = req.body;
    const username = String(packet.user);
    if (!UserManager.isCorrectCode(username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const idToSetTo = String(packet.id);
    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(idToSetTo)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    // idk if db uses a reference to the object or not
    const project = structuredClone(db.get(idToSetTo));
    if ((packet.type === 'votes') && (!project.accepted)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CantVoteUnapprovedProject" });
        return;
    }
    let targetType = 'loves';
    if (packet.type === 'votes') {
        targetType = 'votes';
    }
    // old projects dont have these props set
    if (!Array.isArray(project[targetType])) {
        project[targetType] = [];
    }
    // we add this
    const userValue = encrypt(username);
    let voted = true;
    const decryptedUsernames = DecryptArray(project[targetType]);
    if (decryptedUsernames.includes(username)) {
        // remove the vote
        const newArray = structuredClone(decryptedUsernames);
        const idx = newArray.indexOf(username);
        newArray.splice(idx, 1);
        project[targetType] = EncryptArray(newArray);
        voted = false;
    } else {
        // add encrypted name to the raw list, we dont need to edit decrypted
        project[targetType].push(userValue);
    }
    console.log('updated', targetType, 'on', project.id, 'to', project[targetType].length);
    const featuredVotes = Cast.toNumber(process.env.VotesRequiredForFeature);
    if (project[targetType].length > 50) {
        let badge = "likes";
        if (targetType === 'votes') {
            badge = "votes";
        }
        const newBadges = UserManager.getProperty(project.owner, "badges") ?? [];
        if (!newBadges.includes(badge)) {
            newBadges.push(badge);
            UserManager.setProperty(project.owner, "badges", newBadges);
            UserManager.addMessage(project.owner, {
                type: "newBadge",
                name: badge
            });
        }
    }
    if ((targetType === 'votes') && (project.votes.length >= featuredVotes)) {
        // people lik this project
        let wasFeatured = project.featured;
        project.featured = true;
        if (!wasFeatured) {
            UserManager.addMessage(project.owner, {
                type: "featured",
                projectId: project.id,
                name: `${project.name}` // included for less API calls
            });
        }
        const newBadges = UserManager.getProperty(project.owner, "badges") ?? [];
        if (!newBadges.includes("featured")) {
            newBadges.push("featured");
            UserManager.setProperty(project.owner, "badges", newBadges);
            UserManager.addMessage(project.owner, {
                type: "newBadge",
                name: "featured"
            });
        }
        if (project.featureWebhookSent !== true) {
            project.featureWebhookSent = true;
            const projectImage = String(`https://projects.penguinmod.com/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
            const projectTitle = String(project.name).substring(0, 250);
            const body = JSON.stringify({
                content: `⭐ **${projectTitle}** has been **community featured!** ⭐`,
                embeds: [{
                    title: projectTitle,
                    image: { url: projectImage },
                    color: 16771677,
                    url: String("https://studio.penguinmod.com/#" + String(project.id)),
                    author: {
                        name: String(project.owner).substring(0, 50),
                        icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                        url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
                    }
                }]
            });
            fetch(process.env.DiscordWebhook, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body
            });
        }
    }
    db.set(idToSetTo, project);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "state": voted });
});
app.get('/api/projects/getProjectVote', async function (req, res) {
    const packet = req.query;
    const username = String(packet.user);
    if (!UserManager.isCorrectCode(username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const idToSetTo = String(packet.id);
    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(idToSetTo)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    // idk if db uses a reference to the object or not
    const project = structuredClone(db.get(idToSetTo));
    if (!Array.isArray(project.loves)) {
        project.loves = [];
    }
    if (!Array.isArray(project.votes)) {
        project.votes = [];
    }
    // const userValue = encrypt(username);
    const loved = DecryptArray(project.loves).includes(username);
    const voted = DecryptArray(project.votes).includes(username);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "loved": loved, "voted": voted });
});
// delete uploaded projects
app.get('/api/projects/delete', async function (req, res) {
    // todo: should we make backups of these? remember, uploaded projects are NOT save files
    //       in-progress projects are not going to be a thing so remember that if we decide
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(packet.id)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(packet.id))
    if (project.owner !== packet.approver) {
        if (!AdminAccountUsernames.get(Cast.toString(packet.approver))) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    db.delete(String(packet.id));
    fs.unlink(`./projects/uploaded/p${packet.id}.pmp`, err => {
        if (err) console.log("failed to delete project data for", packet.id, ";", err);
    })
    fs.unlink(`./projects/uploadedImages/p${packet.id}.png`, err => {
        if (err) console.log("failed to delete project image for", packet.id, ";", err);
    })
    console.log(packet.approver, "deleted", packet.id);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// update uploaded projects
app.post('/api/projects/update', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.requestor, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (GlobalRuntimeConfig.get("allowUploadProjects") === false && (!AdminAccountUsernames.get(Cast.toString(packet.requestor)))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "PublishDisabled" });
        return;
    }

    if (UserManager.isBanned(packet.requestor)) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const db = new Database(`${__dirname}/projects/published.json`);
    const id = String(packet.id);
    if (!db.has(id)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NotFound" });
        return;
    }
    const project = db.get(String(id));
    const projectWasApproved = project.accepted;
    if (project.owner !== packet.requestor) {
        if (!AdminAccountUsernames.get(Cast.toString(packet.requestor))) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    let newMetadata = {};
    if (typeof packet.newMeta === "string") {
        newMetadata = SafeJSONParse(packet.newMeta);
        let updatingProject = false;
        if (typeof newMetadata.name === "string") {
            if (ProfanityChecker.containsUnsafeContent(newMetadata.name)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "IllegalWordsUsed" });
                ProfanityChecker.sendHeatLog(newMetadata.name, "projectName", [id, packet.requestor]);
                if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
                return;
            }
            if (newMetadata.name.length < 3 || newMetadata.name.length > 50) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Title3-50Chars" });
                if (DEBUG_logAllFailedData) console.log("Title3-50Chars", packet);
                return;
            }
            project.name = newMetadata.name;
            updatingProject = true;
        }
        if (typeof newMetadata.instructions === "string") {
            if (ProfanityChecker.containsUnsafeContent(newMetadata.instructions)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "IllegalWordsUsed" });
                ProfanityChecker.sendHeatLog(newMetadata.instructions, "projectInstructions", [id, packet.requestor]);
                if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
                return;
            }
            if (newMetadata.instructions && (newMetadata.instructions.length > 4096)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Instructions4096Longer" });
                if (DEBUG_logAllFailedData) console.log("Instructions4096Longer", packet);
                return;
            }
            project.instructions = newMetadata.instructions;
            updatingProject = true;
        }
        if (typeof newMetadata.notes === "string") {
            if (ProfanityChecker.containsUnsafeContent(newMetadata.notes)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "IllegalWordsUsed" });
                ProfanityChecker.sendHeatLog(newMetadata.notes, "projectNotes", [id, packet.requestor]);
                if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
                return;
            }
            if (newMetadata.notes && (newMetadata.notes.length > 4096)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Notes4096Longer" });
                if (DEBUG_logAllFailedData) console.log("Notes4096Longer", packet);
                return;
            }
            project.notes = newMetadata.notes;
            updatingProject = true;
        }
        // if yea then do
        if (updatingProject) {
            project.accepted = true;
            project.featured = false;
            project.updating = true;
            project.date = Date.now();
        }
    }

    const projectBufferData = packet.project;
    if (Cast.isString(projectBufferData)) {
        const buffer = Cast.dataURLToBuffer(projectBufferData);
        if (buffer) {
            const zip = await safeZipParse(buffer);
            if (!zip) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "MissingProjectData" });
                if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
                return;
            }
            // DEBUG
            // fs.writeFile(`./cache/project.json`, await zip.file("project.json").async("string"), (err) => {
            //     if (err) console.error(err);
            // });
            if (!zip.file("project.json")) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "MissingProjectData" });
                if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
                return;
            }
            const rawProjectCodeJSON = await zip.file("project.json").async("string");
            const projectCodeJSON = SafeJSONParse(rawProjectCodeJSON);
            if (!projectCodeJSON.meta) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "MissingProjectData" });
                if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
                return;
            }
            // ok yea project stuff exists
            // are we a low rank?
            const userRank = Cast.toNumber(UserManager.getProperty(packet.requestor, "rank"));
            if (userRank < 1) {
                if (projectCodeJSON.extensions) {
                    // check extensions
                    const isUrlExtension = (extId) => {
                        if (!projectCodeJSON.extensionURLs) return false;
                        return (extId in projectCodeJSON.extensionURLs);
                    };
                    for (let extension of projectCodeJSON.extensions) {
                        let isUrl = isUrlExtension(extension);
                        if (isUrl) {
                            extension = projectCodeJSON.extensionURLs[extension];
                        }
                        if (!checkExtensionIsAllowed(extension, isUrl)) {
                            res.status(403);
                            res.header("Content-Type", 'application/json');
                            res.json({ error: "CannotUseThisExtensionForThisRank", isUrl, extension });
                            if (DEBUG_logAllFailedData) console.log("CannotUseThisExtensionForThisRank", packet);
                            return;
                        }
                    }
                }
            }
            fs.writeFile(`./projects/uploaded/p${id}.pmp`, buffer, (err) => {
                if (err) console.error(err);
            });
        }
        project.accepted = true;
        project.featured = false;
        project.updating = true;
        project.date = Date.now();
    }
    const projectbufferImage = packet.image;
    if (Cast.isString(projectbufferImage)) {
        const buffer = Cast.dataURLToBuffer(projectbufferImage);
        if (buffer) {
            fs.writeFile(`./projects/uploadedImages/p${id}.png`, buffer, (err) => {
                if (err) console.error(err);
            });
        }
        project.accepted = true;
        project.featured = false;
        project.updating = true;
        project.date = Date.now();
    }
    // if project is not accepted, make a log for approvers
    // if (projectWasApproved && !project.accepted) {
    //     // post log
    //     const body = JSON.stringify({
    //         content: `"${project.name}" was updated by ${project.owner}`,
    //         embeds: [{
    //             title: `${project.name} was updated`,
    //             color: 0x00bbff,
    //             fields: [
    //                 {
    //                     name: "Owner",
    //                     value: `${project.owner}`
    //                 },
    //                 {
    //                     name: "ID",
    //                     value: `${project.id}`
    //                 }
    //             ],
    //             author: {
    //                 name: String(project.owner).substring(0, 50),
    //                 icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
    //                 url: String("https://penguinmod.com/profile?user=" + String(project.owner).substring(0, 50))
    //             },
    //             timestamp: new Date().toISOString()
    //         }]
    //     });
    //     fetch(process.env.ApproverLogWebhook, {
    //         method: "POST",
    //         headers: { "Content-Type": "application/json" },
    //         body: body
    //     });
    // }
    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(newMetadata.name, "projectName", [id, packet.requestor]);
    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(newMetadata.instructions, "projectInstructions", [id, packet.requestor]);
    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(newMetadata.notes, "projectNotes", [id, packet.requestor]);
    // set in DB
    db.set(String(id), project);
    console.log(packet.requestor, "updated", id);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
// upload project to the main page
app.post('/api/projects/publish', async function (req, res) {
    const packet = req.body;
    if (GlobalRuntimeConfig.get("allowUploadProjects") === false && (!AdminAccountUsernames.get(Cast.toString(packet.author)))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "PublishDisabled" });
        return;
    }
    if (UserManager.isBanned(packet.author)) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    if (!UserManager.isCorrectCode(packet.author, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        if (DEBUG_logAllFailedData) console.log("Reauthenticate", packet);
        return;
    }

    // cooldown check
    let db = new Database(`${__dirname}/cooldown.json`);
    const cooldown = Number(db.get(Cast.toString(packet.author)));
    if (Date.now() < cooldown) {
        res.status(429);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "TooManyRequests" });
        return;
    }

    if (!(packet.title && packet.author)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingTitleAuthorReference" });
        if (DEBUG_logAllFailedData) console.log("MissingTitleAuthorReference", packet);
        return;
    }
    if (!packet.project) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }

    if (
        (typeof packet.title !== "string") ||
        (typeof packet.author !== "string")
    ) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError" });
        if (DEBUG_logAllFailedData) {
            console.log("FormatError", packet);
            fs.writeFile("./temp.log", JSON.stringify(packet), err => {
                if (err) console.log(err);
            });
        };
        return;
    }
    if (
        !Cast.isString(packet.image) ||
        !Cast.isString(packet.project)
    ) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError2" });
        if (DEBUG_logAllFailedData) {
            console.log("FormatError2", packet);
            fs.writeFile("./temp.log", JSON.stringify(packet), err => {
                if (err) console.log(err);
            });
        };
        return;
    }
    if (packet.instructions && (typeof packet.instructions !== "string")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError" });
        if (DEBUG_logAllFailedData) console.log("FormatError", packet);
        return;
    }
    if (packet.notes && (typeof packet.notes !== "string")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatError" });
        if (DEBUG_logAllFailedData) console.log("FormatError", packet);
        return;
    }
    if (packet.remix && (typeof packet.remix !== "number")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FormatErrorRemixMustBeProjectIdAsNumber" });
        if (DEBUG_logAllFailedData) console.log("FormatErrorRemixMustBeProjectIdAsNumber", packet);
        return;
    }
    if (packet.title.length < 3 || packet.title.length > 50) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Title3-50Chars" });
        if (DEBUG_logAllFailedData) console.log("Title3-50Chars", packet);
        return;
    }
    if (packet.instructions && (packet.instructions.length > 4096)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Instructions4096Longer" });
        if (DEBUG_logAllFailedData) console.log("Instructions4096Longer", packet);
        return;
    }
    if (packet.notes && (packet.notes.length > 4096)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Notes4096Longer" });
        if (DEBUG_logAllFailedData) console.log("Notes4096Longer", packet);
        return;
    }

    if (ProfanityChecker.containsUnsafeContent(packet.title)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        ProfanityChecker.sendHeatLog(packet.title, "projectName", packet.author);
        if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
        return;
    }
    if (packet.instructions && ProfanityChecker.containsUnsafeContent(packet.instructions)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        ProfanityChecker.sendHeatLog(packet.instructions, "projectInstructions", packet.author);
        if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
        return;
    }
    if (packet.notes && ProfanityChecker.containsUnsafeContent(packet.notes)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "IllegalWordsUsed" });
        ProfanityChecker.sendHeatLog(packet.notes, "projectNotes", packet.author);
        if (DEBUG_logAllFailedData) console.log("IllegalWordsUsed", packet);
        return;
    }

    // TODO: these should probably be required at some point
    if (packet.rating) {
        switch (packet.rating) {
            case 'e': // everyone
            case 'E': // everyone
            case 'd': // E+10 everyone above 10yo
            case 'D': // E+10 everyone above 10yo
            case 't': // teens
            case 'T': // teens
                break;
            default:
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "InvalidRating" });
                if (DEBUG_logAllFailedData) console.log("InvalidRating", packet);
                return;
        }
    }
    if (packet.restrictions && (!Array.isArray(packet.restrictions))) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidRestrictionFormat" });
        if (DEBUG_logAllFailedData) console.log("InvalidRestrictionFormat", packet);
        return;
    }
    if (packet.restrictions) {
        const usedRestrictions = [];
        for (const restriction of packet.restrictions) {
            switch (restriction) {
                case 'flash':
                case 'blood':
                case 'scary':
                case 'swear':
                    if (usedRestrictions.includes(restriction)) {
                        res.status(400);
                        res.header("Content-Type", 'application/json');
                        res.json({ "error": "CanOnlyUseRestrictionOnce" });
                        if (DEBUG_logAllFailedData) console.log("CanOnlyUseRestrictionOnce", packet);
                        return;
                    }
                    usedRestrictions.push(restriction);
                    break;
                default:
                    res.status(400);
                    res.header("Content-Type", 'application/json');
                    res.json({ "error": "InvalidRestriction" });
                    if (DEBUG_logAllFailedData) console.log("InvalidRestriction", packet);
                    return;
            }
        }
    }

    const project = Cast.dataURLToBuffer(packet.project);
    if (!project) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    const zip = await safeZipParse(project);
    if (!zip) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    // DEBUG
    // fs.writeFile(`./cache/project.json`, await zip.file("project.json").async("string"), (err) => {
    //     if (err) console.error(err);
    // });
    if (!zip.file("project.json")) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    const rawProjectCodeJSON = await zip.file("project.json").async("string");
    const projectCodeJSON = SafeJSONParse(rawProjectCodeJSON);
    if (!projectCodeJSON.meta) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "MissingProjectData" });
        if (DEBUG_logAllFailedData) console.log("MissingProjectData", packet);
        return;
    }
    // ok yea project stuff exists
    // are we a low rank?
    const userRank = Cast.toNumber(UserManager.getProperty(packet.author, "rank"));
    if (userRank < 1) {
        if (projectCodeJSON.extensions) {
            // check extensions
            const isUrlExtension = (extId) => {
                if (!projectCodeJSON.extensionURLs) return false;
                return (extId in projectCodeJSON.extensionURLs);
            };
            for (let extension of projectCodeJSON.extensions) {
                let isUrl = isUrlExtension(extension);
                if (isUrl) {
                    extension = projectCodeJSON.extensionURLs[extension];
                }
                if (!checkExtensionIsAllowed(extension, isUrl)) {
                    res.status(403);
                    res.header("Content-Type", 'application/json');
                    res.json({ error: "CannotUseThisExtensionForThisRank", isUrl, extension });
                    if (DEBUG_logAllFailedData) console.log("CannotUseThisExtensionForThisRank", packet);
                    return;
                }
            }
        }
    }

    // set cooldown
    db.set(packet.author, Date.now() + 480000);

    // create project id
    db = new Database(`${__dirname}/projects/published.json`);
    let _id = Math.round(100000 + (Math.random() * 9999999999999));
    if (db.has(String(_id))) {
        while (db.has(String(_id))) _id++;
    }
    const id = _id;

    // we already checked earlier if this was a valid project
    fs.writeFile(`./projects/uploaded/p${id}.pmp`, project, (err) => {
        if (err) console.error(err);
    });
    const image = Cast.dataURLToBuffer(packet.image);
    if (image) {
        fs.writeFile(`./projects/uploadedImages/p${id}.png`, image, (err) => {
            if (err) console.error(err);
        });
    }

    // save in DB
    db.set(String(id), {
        id: id, // surprisingly this is useful to keep the id in the key named the id (unless my code is bad)
        name: packet.title,
        instructions: packet.instructions,
        notes: packet.notes,
        owner: packet.author,
        // we dont save image in the project anymore
        // image: packet.image, // base64 url
        // project: packet.project, // base64 url (not saved here since we save it in a file instead)
        featured: false, // if true, display it golden in pm or something idk
        accepted: true, // NO LONGER FALSE, used to be: must be accepted before it can appear on the public page

        remix: packet.remix,

        date: Date.now(), // set the creation date to now

        views: 0, // how many times the project file was grabbed in the api
        loves: [], // list of (encrypted) usernames who loved the project
        votes: [], // list of (encrypted) usernames who voted for the project to be featured

        rating: packet.rating, // E, E+10, T ratings (or ? for old projects)
        restrictions: packet.restrictions, // array of restrictions on this project (ex: blood, flashing lights)
    });

    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(packet.title, "projectName", [id, packet.author]);
    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(packet.instructions, "projectInstructions", [id, packet.author]);
    ProfanityChecker.checkAndWarnPotentiallyUnsafeContent(packet.notes, "projectNotes", [id, packet.author]);

    // log for approvers
    // const body = JSON.stringify({
    //     content: `"${packet.title}" was uploaded by ${packet.author}`,
    //     embeds: [{
    //         title: `${packet.title} was uploaded`,
    //         color: 0x00bbff,
    //         fields: [
    //             {
    //                 name: "Owner",
    //                 value: `${packet.author}`
    //             },
    //             {
    //                 name: "ID",
    //                 value: `${id}`
    //             }
    //         ],
    //         author: {
    //             name: String(packet.author).substring(0, 50),
    //             icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.author).substring(0, 50)),
    //             url: String("https://penguinmod.com/profile?user=" + String(packet.author).substring(0, 50))
    //         },
    //         timestamp: new Date().toISOString()
    //     }]
    // });
    // fetch(process.env.ApproverLogWebhook, {
    //     method: "POST",
    //     headers: { "Content-Type": "application/json" },
    //     body: body
    // });

    // actually say the thing!!!!!!!!!!
    res.status(200);
    res.json({ "published": id });
    console.log(packet.title, "was published!");
});
// gets a published project
const viewsIpStorage = {};
app.get('/api/projects/getPublished', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const requestIp = req.ip;
    if ((req.query.id) == null) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "NoIDSpecified" });
        return;
    }
    db = new Database(`${__dirname}` + "/projects/published" + ".json");
    if (db.has(String(req.query.id))) {
        const project = db.get(String(req.query.id));
        if (String(req.query.type) == "file") {
            fs.readFile(`./projects/uploaded/p${project.id}.pmp`, (err, data) => {
                if (err) {
                    res.status(500);
                    res.header("Content-Type", 'text/plain');
                    res.send(`<UnknownError err="${err}">`);
                    return;
                }
                if (typeof project.views !== "number") {
                    project.views = 0;
                }
                if (!Array.isArray(viewsIpStorage[Cast.toString(project.id)])) {
                    viewsIpStorage[Cast.toString(project.id)] = [];
                }
                const ipStorage = viewsIpStorage[Cast.toString(project.id)];
                if (!ipStorage.includes(requestIp)) {
                    project.views += 1;
                    ipStorage.push(requestIp);
                }
                db.set(String(req.query.id), project);
                res.status(200);
                res.header("Content-Type", 'application/x.scratch.sb3');
                res.send(data);
            });
            return;
        }
        const clone = structuredClone(project);
        clone.loves = Array.isArray(project.loves) ? project.loves.length : 0;
        clone.votes = Array.isArray(project.votes) ? project.votes.length : 0;
        res.status(200);
        res.json(clone);
    } else {
        res.status(404);
        res.json({ "error": "NotFound" });
    }
});
// sorts the projects into a nice array of pages
app.get('/api/projects/search', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const db = new Database(`${__dirname}/projects/published.json`);

    const projectOwnerRequired = req.query.user;
    const projectSearchingName = req.query.includes;
    const mustBeFeatured = req.query.featured;
    const shouldReturnRandomProject = Cast.toBoolean(req.query.random);
    const sortingBy = Cast.toString(req.query.sortby);

    // add featured projects first but also sort them by date
    // to do that we just sort all projects then add them to a seperate array
    const featuredProjects = [];
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        const latestValue = sproject.date - project.date;
        if (sortingBy === 'likes') {
            return (sproject.loves || []).length - (project.loves || []).length;
        }
        if (sortingBy === 'votes') {
            return (sproject.votes || []).length - (project.votes || []).length;
        }
        if (sortingBy === 'views') {
            return (sproject.views || 0) - (project.views || 0);
        }
        return latestValue;
    }).filter(proj => proj.accepted === true).filter(project => {
        if (projectSearchingName) {
            const projectName = Cast.toString(project.name).toLowerCase().trim();
            const searchQueryName = Cast.toString(projectSearchingName).toLowerCase().trim();
            const tagMatches = searchQueryName.match(/#[^\s]+/gmi);
            let tagsFound = false;
            if (tagMatches) {
                const projectDescription = Cast.toString(project.instructions).toLowerCase().trim()
                    + ` ${Cast.toString(project.notes).toLowerCase().trim()}`;
                tagsFound = tagMatches.some(tag => projectDescription.includes(tag));
            }
            return tagsFound || projectName.includes(searchQueryName);
        }
        if (typeof projectOwnerRequired !== "string") {
            return true;
        }
        return project.owner === projectOwnerRequired;
    }).filter(project => {
        if (Cast.toString(mustBeFeatured) === 'exclude') {
            // returning here removes featured projects
            return project.featured != true;
        }
        if (project.featured) {
            featuredProjects.push(project);
        }
        if (Cast.toString(mustBeFeatured) === 'true') {
            // returning false here removes normal projects
            return false;
        }
        return project.featured != true;
    });
    // we set the array to featuredProjectsArray.concat(array) instead of array.concat(featuredProjectsArray)
    // because otherwise the featured projects would be after the normal projects
    const returnArray = featuredProjects.concat(projects);
    if (shouldReturnRandomProject === true) {
        // return a random project in this array
        const project = RandomArrayItem(returnArray);
        res.header("Content-Type", 'application/json');
        res.status(200);
        res.json(project ? {"id": project.id} : {"error": "NoProjectsFound"});
        return;
    }
    // make project list
    // new ProjectList() with .toJSON will automatically cut the pages for us
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
const recommendedProjectTags = require("./projecttags.json");
app.get('/api/projects/frontPage', async function (req, res) {
    if (GlobalRuntimeConfig.get("allowGetProjects") === false) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
    }

    const db = new Database(`${__dirname}/projects/published.json`);

    // get the list of all projects
    /**
     * @type {Array<object>}
     */
    const allProjects = db.all()
        .map(value => { return value.data })
        .sort((project, sproject) => sproject.date - project.date)
        .filter(proj => proj.accepted === true);

    const randomTag = RandomArrayItem(recommendedProjectTags.tags);
    const returnedData = {
        featured: [],
        voted: [],
        liked: [],
        viewed: [],
        latest: [],
        tagged: [],
        selectedTag: randomTag
    };

    // start filling this out
    returnedData.featured = allProjects
        .filter(proj => proj.featured)
        .slice(0, 15)
        .map(proj => ProjectList.sanitizeProjectObject(proj));
    returnedData.voted = allProjects
        .filter(proj => !proj.featured)
        .filter(proj => proj.votes && proj.votes.length > 5) // too low to appear here
        .sort((project, sproject) => sproject.votes.length - project.votes.length)
        .slice(0, 15)
        .map(proj => ProjectList.sanitizeProjectObject(proj));
    returnedData.liked = allProjects
        .filter(proj => !proj.featured)
        .filter(proj => proj.loves && proj.loves.length > 5) // too low to appear here
        .sort((project, sproject) => sproject.loves.length - project.loves.length)
        .slice(0, 15)
        .map(proj => ProjectList.sanitizeProjectObject(proj));
    returnedData.viewed = allProjects
        .filter(proj => !proj.featured)
        .filter(proj => proj.views && proj.views > 30) // too low to appear here
        .sort((project, sproject) => sproject.views - project.views)
        .slice(0, 15)
        .map(proj => ProjectList.sanitizeProjectObject(proj));
    returnedData.tagged = allProjects
        .filter(project => {
            const projectName = Cast.toString(project.name).toLowerCase().trim();
            const projectDescription = (Cast.toString(project.instructions)
                + ` ${Cast.toString(project.notes)}`).toLowerCase().trim();
            return projectDescription.includes(`#${randomTag}`) || projectName.includes(`#${randomTag}`);
        })
        .slice(0, 15)
        .map(proj => ProjectList.sanitizeProjectObject(proj));
    returnedData.latest = allProjects
        .slice(0, 15)
        .map(proj => ProjectList.sanitizeProjectObject(proj));

    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returnedData);
});

app.listen(port, () => console.log('Started server on port ' + port));

// return;
require('dotenv').config();

// todo: move to external file?
const AdminAccountUsernames = [
    "JeremyGamer13",
    "JGamerTesting",
    "jwklongYT",
    "RedMan13",
    "know0your0true0color",
    "hacker_anonimo",
    "ianyourgod",
    "yeeter2001",
    "JoshAtticus",

    // "debug",

    // add your scratch username here and you
    // will be able to use the admin panel
];

// todo: move to external file and/or add endpoint/method to add users
const ApproverUsernames = [
    "JGamerFunkin",
    "G1nX",
    "birdman2354",
    "infintyrussia",
    "Disheveled_cat",
    "poprockdev",
    "CMC_corp",

    "insanetaco2000",
    "puzzlingGGG",
    "ItzzEndr",
    "TheShovel",
    "Dicuorooja",
    "something_nice",
    "booger444",
    // add scratch usernames here and they
    // will be able to approve uploaded projects
];

const BlockedIPs = require("./blockedips.json");

const fs = require("fs");
const jimp = require("jimp");
const Database = require("easy-json-database");
const Cast = require("./classes/Cast.js");

const DEBUG_logAllFailedData = Cast.toBoolean(process.env.LogFailedData);

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const app = express();
const port = 8080;

const { encrypt, decrypt } = require("./utilities/encrypt.js");

const UserManager = require("./classes/UserManager.js");
// const UserStorage = require("./classes/UserStorage.js");
// const StorageSpace = new UserStorage(32000000, 3); // 32 mb per data piece, 3 keys per container
UserManager.load(); // should prevent logouts

const ProjectList = require("./classes/ProjectList.js");
const GenericList = require("./classes/GenericList.js");

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

function Deprecation(res, reason = "") {
    res.status(400);
    res.header("Content-Type", 'application/json');
    res.json({
        error: "Deprecated Endpoint",
        reason
    });
}
function escapeXML(unsafe) {
    if (typeof unsafe !== 'string') {
        if (unsafe) {
            // This happens when we have hacked blocks from 2.0
            // See #1030
            unsafe = String(unsafe);
        } else {
            console.error(`Unexptected type ${typeof unsafe} in xmlEscape at: ${new Error().stack}`)
            return unsafe;
        }
    }
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
    console.log(`${req.ip}: ${req.originalUrl}`);
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

app.get('/', async function (_, res) {
    res.redirect('https://penguinmod.site');
});
app.get('/robots.txt', async function (_, res) {
    res.sendFile(path.join(__dirname, './robots.txt'));
});

// API metadata
app.get('/api', async function (_, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.sendFile(path.join(__dirname, './metadata.json'));
});
// PING COMMAND TO CHECK IF API IS WORKING (LOL)
app.get('/api/ping', async function (_, res) {
    res.send("Pong!")
});
const projectTemplate = fs.readFileSync('./project.html').toString()
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

// security stuff i guess :idk_man:
app.get('/api/users/isBanned', async function (req, res) {
    if (typeof req.query.username != "string") {
        res.status(400)
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidRequest" })
        return
    }
    res.status(200)
    res.header("Content-Type", 'application/json');
    res.json({ "banned": UserManager.isBanned(req.query.username) })
})

app.get('/api/projects/getAll', async function (req, res) {
    Deprecation(res, "Projects have seperate endpoints for approved and unapproved");
});
// get approved projects
app.get('/api/projects/getApproved', async function (req, res) {
    const db = new Database(`${__dirname}/projects/published.json`);
    // this is explained in paged api but basically just add normal projects to featured projects
    // because otherwise featured projects would come after normal projects
    const featuredProjects = [];
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted == true).filter(project => {
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
    function grabArray() {
        const db = new Database(`${__dirname}/projects/published.json`)
        // this is explained in paged api but basically just add normal projects to featured projects
        // because otherwise featured projects would come after normal projects
        const featuredProjects = [];
        const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
            return sproject.date - project.date;
        }).filter(proj => proj.accepted == true).filter(project => {
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
})
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
        !AdminAccountUsernames.includes(packet.user)
        && !ApproverUsernames.includes(packet.user)
    ) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "ThisAccountCannotAccessThisInformation" });
        return;
    }
    const db = new Database(`${__dirname}/projects/published.json`)
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted == false);
    let returnArray = projects;
    if (Cast.toBoolean(req.query.reverse)) {
        returnArray = structuredClone(returnArray).reverse();
    }
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
})
// pm wrappers so that pm code doesnt need to be changed in a major way
app.get('/api/pmWrapper/projects', async function (req, res) {
    const db = new Database(`${__dirname}/projects/published.json`)
    // this is explained in paged api but basically just add normal projects to featured projects
    // because otherwise featured projects would come after normal projects
    const featuredProjects = []
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).map(project => {
        return { id: project.id, name: project.name, author: { username: project.owner }, accepted: project.accepted, featured: project.featured };
    }).filter(proj => proj.accepted == true).filter(project => {
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
app.get('/api/pmWrapper/remixes', async function (req, res) {
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
    }).filter(proj => proj.remix == packet.id).filter(proj => proj.accepted == true);
    const projectsList = new ProjectList(json);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});
app.get('/api/pmWrapper/iconUrl', async function (req, res) {
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
app.get('/api/pmWrapper/getProject', async function (req, res) {
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
// const CachedScratchUsers = {}
// let ScratchRequestQueue = 0
app.get('/api/pmWrapper/scratchUserImage', async function (req, res) {
    Deprecation(res, "Use trampoline.turbowarp.org/avatars/by-username instead, this endpoint has been removed to reduce network usage.");
    // if (!req.query.username) {
    //     res.status(400);
    //     res.json({ "error": "UsernameNotSpecified" });
    //     return;
    // }
    // const usableName = Cast.toString(req.query.username);
    // if (CachedScratchUsers[usableName] != null) {
    //     const image = CachedScratchUsers[usableName];
    //     res.status(200);
    //     res.contentType('image/png');
    //     res.send(image);
    //     return;
    // }
    // if (ScratchRequestQueue < 0) ScratchRequestQueue = 0;
    // ScratchRequestQueue += 400;
    // setTimeout(() => {
    //     ScratchRequestQueue -= 400;
    //     fetch(`https://trampoline.turbowarp.org/avatars/by-username/${usableName}`).then(serverResponse => {
    //         serverResponse.arrayBuffer().then(arrayBuffer => {
    //             const buffer = Buffer.from(arrayBuffer);
    //             CachedScratchUsers[usableName] = buffer;
    //             res.status(200);
    //             res.contentType('image/png');
    //             res.send(buffer);
    //         }).catch(err => {
    //             res.status(500);
    //             res.json({ error: "UnexpectedError", realerror: err });
    //         });
    //     }).catch(() => {
    //         res.status(500);
    //         res.json({ error: "FailedToAccessTrampoline" });
    //         return;
    //     })
    // }, ScratchRequestQueue);
});
// scratch auth implementation
app.get('/api/users/login', async function (req, res) {
    const privateCode = Cast.toString(req.query.privateCode);
    UserManager.verifyCode(privateCode).then(response => {
        // check if it is a malicious site
        // note: malicious sites cannot read the private code in the URL if it is the right redirect
        //       thank you cors, you finally did something useful

        // malicious APPS could, but at that point your just :trollface:d so :idk_man:
        const invalidRedirect = response.redirect !== 'https://projects.penguinmod.site/api/users/login';
        if ((!response.valid) || (invalidRedirect)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidLogin" });
            if (invalidRedirect) {
                console.log(response.redirect, "tried to falsely authenticate", response.username);
            }
            return;
        }
        // todo: we should clear the login after a couple days or so
        UserManager.setCode(response.username, privateCode);
        // close window by opening success.html
        res.header("Content-Type", 'text/html');
        res.status(200);
        res.sendFile(path.join(__dirname, "./success.html"));
    }).catch(() => {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidLogin" });
    });
});
app.get('/api/users/loginLocal', async function (req, res) {
    const privateCode = Cast.toString(req.query.privateCode);
    UserManager.verifyCode(privateCode).then(response => {
        // check if it is a malicious site
        // note: malicious sites cannot read the private code in the URL if it is the right redirect
        //       thank you cors, you finally did something useful

        // malicious APPS could, but at that point your just :trollface:d so :idk_man:
        const invalidRedirect =
            response.redirect !== 'https://projects.penguinmod.site/api/users/loginLocal'
            && response.redirect !== 'http://localhost:8080/api/users/loginLocal';
        if ((!response.valid) || (invalidRedirect)) {
            res.status(400);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "InvalidLogin" });
            if (invalidRedirect) {
                console.log(response.redirect, "tried to falsely authenticate", response.username);
            }
            return;
        }
        // todo: we should clear the login after a couple days or so
        UserManager.setCode(response.username, privateCode);
        // close window by opening success.html
        res.header("Content-Type", 'text/html');
        res.status(200);
        res.sendFile(path.join(__dirname, "./success_local.html"));
    }).catch(() => {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "InvalidLogin" });
    });
});
// logout
app.get('/api/users/logout', (req, res) => {
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
app.get('/api/users/usernameFromCode', async function (req, res) {
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
    res.json({
        "username": username,
        "admin": AdminAccountUsernames.includes(username),
        "approver": ApproverUsernames.includes(username)
    });
});
// extra stuff
app.get('/api/users/isAdmin', async function (req, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "admin": AdminAccountUsernames.includes(req.query.username) });
});
app.get('/api/users/isApprover', async function (req, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({
        "approver": ApproverUsernames.includes(req.query.username)
            || AdminAccountUsernames.includes(req.query.username)
    });
});
app.get('/api/users/getMyProjects', async function (req, res) {
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
})
// store temporary data
app.post('/api/users/store', async function (_, res) {
    Deprecation(res, "Unused for quite some time, no longer needs to exist");
});
app.get('/api/users/getstore', async function (req, res) {
    Deprecation(res, "Unused for quite some time, no longer needs to exist");
});

// MESSAGES
app.get('/api/users/getMessages', async function (req, res) {
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
// we might not actually need this endpoint tbh
app.post('/api/users/addMessage', async function (req, res) {
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
    const username = packet.username;
    const target = packet.target;
    switch (unsafeMessage.type) {
        case 'custom':
            if (!AdminAccountUsernames.includes(username)) return notallowed();
            if (typeof unsafeMessage.text !== "string") return invalidate();
            UserManager.addMessage(target, {
                type: unsafeMessage.type,
                text: unsafeMessage.text
            });
            break;
        default:
            return invalidate();
    }

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
});
app.get('/api/users/getMessageCount', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    const messages = UserManager.getUnreadMessages(packet.username);
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
app.get('/api/users/getBadges', async function (req, res) {
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
app.post('/api/users/setBadges', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.username, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return;
    }
    if (!AdminAccountUsernames.includes(packet.username)) {
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

// following
app.get('/api/users/getFollowerCount', async function (req, res) {
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
app.get('/api/users/isFollowing', async function (req, res) {
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
    if (!AdminAccountUsernames.includes(packet.username)) {
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
                url: String("https://penguinmod.site/profile?user=" + String(bannedUser).substring(0, 50))
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
    if (!AdminAccountUsernames.includes(packet.username)) {
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
                url: String("https://penguinmod.site/profile?user=" + String(bannedUser).substring(0, 50))
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
                url: String("https://penguinmod.site/profile?user=" + String(packet.username).substring(0, 50))
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
        !AdminAccountUsernames.includes(packet.approver)
        && !ApproverUsernames.includes(packet.approver)
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
                url: String("https://penguinmod.site/profile?user=" + String(packet.username).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
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
        !AdminAccountUsernames.includes(packet.approver)
        && !ApproverUsernames.includes(packet.approver)
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
    const project = JSON.parse(JSON.stringify(db.get(packet.id)));
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
        const projectImage = String(`https://projects.penguinmod.site/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
        const body = JSON.stringify({
            content: `"${project.name}" was approved by ${packet.approver}`,
            embeds: [{
                title: `${project.name} was approved`,
                color: 0x00ff00,
                image: { url: projectImage },
                url: "https://studio.penguinmod.site/#" + project.id,
                fields: [
                    {
                        name: "Approved by",
                        value: `${packet.approver}`
                    }
                ],
                author: {
                    name: String(project.owner).substring(0, 50),
                    icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                    url: String("https://penguinmod.site/profile?user=" + String(project.owner).substring(0, 50))
                },
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.ApproverLogWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(JSON.parse(body))
        });
    }

    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
    if (Cast.toBoolean(req.query.webhook) === false) return;
    const projectImage = String(`https://projects.penguinmod.site/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
    const body = JSON.stringify({
        content: `A project was ${isUpdated ? "updated" : (isRemix ? "remixed" : "approved")}!`,
        embeds: [{
            title: String(project.name).substring(0, 250),
            description: String(project.instructions + "\n\n" + project.notes).substring(0, 2040),
            image: { url: projectImage },
            color: (isUpdated ? 14567657 : (isRemix ? 6618880 : 41440)),
            url: String("https://studio.penguinmod.site/#" + String(project.id)),
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://penguinmod.site/profile?user=" + String(project.owner).substring(0, 50))
            }
        }]
    });
    fetch(process.env.DiscordWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
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
        !AdminAccountUsernames.includes(packet.approver)
        && !ApproverUsernames.includes(packet.approver)
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
    if (project.accepted) {
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CannotRejectApprovedProject" });
        return;
    }
    // post log
    const body = JSON.stringify({
        content: `"${project.name}" was rejected by ${packet.approver}`,
        embeds: [{
            title: `${project.name} was rejected`,
            color: 0xff0000,
            fields: [
                {
                    name: "Rejected by",
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
                url: String("https://penguinmod.site/profile?user=" + String(project.owner).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
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
        !AdminAccountUsernames.includes(packet.approver)
        && !ApproverUsernames.includes(packet.approver)
    ) {
        // TODO: allow project owner to download
        res.status(403);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "FeatureDisabledForThisAccount" });
        return;
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
    if (!AdminAccountUsernames.includes(packet.approver)) {
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
                "accepted": false,
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
                accepted: false,
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
            accepted: false,
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
// feature uploaded projects
app.get('/api/projects/feature', async function (req, res) {
    const packet = req.query;
    if (!UserManager.isCorrectCode(packet.approver, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
        return
    }
    if (!AdminAccountUsernames.includes(packet.approver)) {
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
    const project = JSON.parse(JSON.stringify(db.get(idToSetTo)));
    if (!project.accepted) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CantFeatureUnapprovedProject" });
        return;
    }
    if (project.votes.length < 6) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "CantFeatureProjectWithLessThan6Votes" });
        return;
    }
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
    const projectImage = String(`https://projects.penguinmod.site/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
    const projectTitle = String(project.name).substring(0, 250);
    const body = JSON.stringify({
        content: `⭐ **${projectTitle}** was **featured**! ⭐`,
        embeds: [{
            title: projectTitle,
            image: { url: projectImage },
            color: 16771677,
            url: String("https://studio.penguinmod.site/#" + String(project.id)),
            author: {
                name: String(project.owner).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                url: String("https://penguinmod.site/profile?user=" + String(project.owner).substring(0, 50))
            }
        }]
    });
    fetch(process.env.DiscordWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
    });
    // .then(res => res.text().then(t => console.log("WebhookResponse",res.status,t))).catch(err => console.log("FailedWebhookSend", err))
})
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
            const projectImage = String(`https://projects.penguinmod.site/api/pmWrapper/iconUrl?id=${project.id}&rn=${Math.round(Math.random() * 9999999)}`);
            const projectTitle = String(project.name).substring(0, 250);
            const body = JSON.stringify({
                content: `⭐ **${projectTitle}** has been **community featured!** ⭐`,
                embeds: [{
                    title: projectTitle,
                    image: { url: projectImage },
                    color: 16771677,
                    url: String("https://studio.penguinmod.site/#" + String(project.id)),
                    author: {
                        name: String(project.owner).substring(0, 50),
                        icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                        url: String("https://penguinmod.site/profile?user=" + String(project.owner).substring(0, 50))
                    }
                }]
            });
            fetch(process.env.DiscordWebhook, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(JSON.parse(body))
            });
        }
    }
    db.set(idToSetTo, project);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "state": voted });
})
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
    const project = JSON.parse(JSON.stringify(db.get(idToSetTo)));
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
})
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
        if (!AdminAccountUsernames.includes(packet.approver)) {
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
// todo: replace /approve's newMeta stuff with this endpoint?
app.post('/api/projects/update', async function (req, res) {
    const packet = req.body;
    if (!UserManager.isCorrectCode(packet.requestor, packet.passcode)) {
        res.status(400);
        res.header("Content-Type", 'application/json');
        res.json({ "error": "Reauthenticate" });
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
        if (!AdminAccountUsernames.includes(packet.requestor)) {
            res.status(403);
            res.header("Content-Type", 'application/json');
            res.json({ "error": "FeatureDisabledForThisAccount" });
            return;
        }
    }
    if (typeof packet.newMeta === "string") {
        const newMetadata = SafeJSONParse(packet.newMeta);
        let updatingProject = false;
        if (typeof newMetadata.name === "string") {
            project.name = newMetadata.name;
            if (newMetadata.name.length < 3 || newMetadata.name.length > 50) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Title3-50Chars" });
                if (DEBUG_logAllFailedData) console.log("Title3-50Chars", packet);
                return;
            }
            updatingProject = true;
        }
        if (typeof newMetadata.instructions === "string") {
            project.instructions = newMetadata.instructions;
            if (newMetadata.instructions && (newMetadata.instructions.length > 4096)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Instructions4096Longer" });
                if (DEBUG_logAllFailedData) console.log("Instructions4096Longer", packet);
                return;
            }
            updatingProject = true;
        }
        if (typeof newMetadata.notes === "string") {
            project.notes = newMetadata.notes;
            if (newMetadata.notes && (newMetadata.notes.length > 4096)) {
                res.status(400);
                res.header("Content-Type", 'application/json');
                res.json({ "error": "Notes4096Longer" });
                if (DEBUG_logAllFailedData) console.log("Notes4096Longer", packet);
                return;
            }
            updatingProject = true;
        }
        // if yea then do
        if (updatingProject) {
            project.accepted = false;
            project.featured = false;
            project.updating = true;
            project.date = Date.now();
        }
    }

    // todo: validate project data?
    const projectBufferData = packet.project;
    if (Cast.isString(projectBufferData)) {
        const buffer = Cast.dataURLToBuffer(projectBufferData);
        if (buffer) {
            fs.writeFile(`./projects/uploaded/p${id}.pmp`, buffer, (err) => {
                if (err) console.error(err);
            });
        }
        project.accepted = false;
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
        project.accepted = false;
        project.featured = false;
        project.updating = true;
        project.date = Date.now();
    }
    // if project is not accepted, make a log for approvers
    if (projectWasApproved && !project.accepted) {
        // post log
        const body = JSON.stringify({
            content: `"${project.name}" was updated by ${project.owner}`,
            embeds: [{
                title: `${project.name} was updated`,
                color: 0x00bbff,
                fields: [
                    {
                        name: "Owner",
                        value: `${project.owner}`
                    },
                    {
                        name: "ID",
                        value: `${project.id}`
                    }
                ],
                author: {
                    name: String(project.owner).substring(0, 50),
                    icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(project.owner).substring(0, 50)),
                    url: String("https://penguinmod.site/profile?user=" + String(project.owner).substring(0, 50))
                },
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.ApproverLogWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: body
        });
    }
    // set in DB
    db.set(String(id), project);
    console.log(packet.requestor, "updated", id);
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "success": true });
})
// upload project to the main page
const UploadsDisabled = Cast.toBoolean(process.env.UploadsDisabled);
app.post('/api/projects/publish', async function (req, res) {
    const packet = req.body;
    if (UploadsDisabled && (!AdminAccountUsernames.includes(packet.author))) {
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
    const cooldown = Number(db.get(packet.author));
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

    // set cooldown
    db.set(packet.author, Date.now() + 480000);

    // create project id
    db = new Database(`${__dirname}/projects/published.json`);
    let _id = Math.round(100000 + (Math.random() * 9999999999999));
    if (db.has(String(_id))) {
        while (db.has(String(_id))) _id++;
    }
    const id = _id;

    const project = Cast.dataURLToBuffer(packet.project);
    if (project) {
        fs.writeFile(`./projects/uploaded/p${id}.pmp`, project, (err) => {
            if (err) console.error(err);
        })
    }
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
        accepted: false, // must be accepted before it can appear on the public page

        remix: packet.remix,

        date: Date.now(), // set the creation date to now

        views: 0, // how many times the project file was grabbed in the api
        loves: [], // list of (encrypted) usernames who loved the project
        votes: [], // list of (encrypted) usernames who voted for the project to be featured

        rating: packet.rating, // E, E+10, T ratings (or ? for old projects)
        restrictions: packet.restrictions, // array of restrictions on this project (ex: blood, flashing lights)
    })

    // log for approvers
    const body = JSON.stringify({
        content: `"${packet.title}" was uploaded by ${packet.author}`,
        embeds: [{
            title: `${packet.title} was uploaded`,
            color: 0x00bbff,
            fields: [
                {
                    name: "Owner",
                    value: `${packet.author}`
                },
                {
                    name: "ID",
                    value: `${id}`
                }
            ],
            author: {
                name: String(packet.author).substring(0, 50),
                icon_url: String("https://trampoline.turbowarp.org/avatars/by-username/" + String(packet.author).substring(0, 50)),
                url: String("https://penguinmod.site/profile?user=" + String(packet.author).substring(0, 50))
            },
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body
    });

    // actually say the thing!!!!!!!!!!
    res.status(200);
    res.json({ "published": id });
    console.log(packet.title, "was published!");
})
// gets a published project
const viewsIpStorage = {};
app.get('/api/projects/getPublished', async function (req, res) {
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
app.get('/api/projects/paged', async function (req, res) {
    Deprecation(res, "Not useful if pagination requires multiple requests, use /search for filtering and /getApproved for normal list");
    // db = new Database(`${__dirname}` + "/projects/published.json");
    // res.header("Content-Type", 'application/json');
    // res.status(200)
    // const projectOwnerRequired = req.query.user
    // const projectSearchingName = req.query.includes
    // const featuredProjectsArray = []
    // let array = db.all().map(obj => obj.data).sort((project, sproject) => {
    //     return sproject.date - project.date
    // }).filter(proj => proj.accepted == true).filter(project => {
    //     if (projectSearchingName) {
    //         return String(project.name).toLowerCase().includes(String(projectSearchingName).toLowerCase())
    //     }
    //     if (typeof projectOwnerRequired !== "string") {
    //         return true
    //     }
    //     return project.owner === projectOwnerRequired
    // }).filter(project => {
    //     // add featured projects first but also sort them by date
    //     // to do that we just add them to a seperate array and sort that
    //     if (project.featured) {
    //         featuredProjectsArray.push(project)
    //     }
    //     return project.featured != true
    // })
    // // sort featured projects
    // featuredProjectsArray.sort((project, sproject) => {
    //     return sproject.date - project.date
    // })
    // // we set the array to featuredProjectsArray.concat(array) instead of array.concat(featuredProjectsArray)
    // // because otherwise the featured projects would be after the normal projects
    // array = featuredProjectsArray.concat(array)

    // const maxItems = req.query.length ? Number(req.query.length) : 12
    // if (maxItems <= 0) return res.json([])

    // const pagesArray = []
    // let page = []

    // for (let index = 0; index < array.length; index++) {
    //     const item = array[index]
    //     page.push(item)
    //     if (index % maxItems == maxItems - 1) {
    //         pagesArray.push(page)
    //         page = []
    //         continue
    //     }
    //     if (index >= array.length - 1 && page.length != maxItems) {
    //         pagesArray.push(page)
    //         page = []
    //         continue
    //     }
    // }

    // res.json(pagesArray)
});
// sorts the projects into a nice array of pages
app.get('/api/projects/search', async function (req, res) {
    const db = new Database(`${__dirname}/projects/published.json`);

    const projectOwnerRequired = req.query.user;
    const projectSearchingName = req.query.includes;
    const mustBeFeatured = req.query.featured;

    // add featured projects first but also sort them by date
    // to do that we just sort all projects then add them to a seperate array
    const featuredProjects = [];
    const projects = db.all().map(value => { return value.data }).sort((project, sproject) => {
        return sproject.date - project.date;
    }).filter(proj => proj.accepted == true).filter(project => {
        if (projectSearchingName) {
            const projectName = Cast.toString(project.name).toLowerCase();
            const ownerName = Cast.toString(projectSearchingName).toLowerCase();
            return projectName.includes(ownerName);
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
    // make project list
    // new ProjectList() with .toJSON will automatically cut the pages for us
    const projectsList = new ProjectList(returnArray);
    const returning = projectsList.toJSON(true, Cast.toNumber(req.query.page));
    res.header("Content-Type", 'application/json');
    res.status(200);
    res.json(returning);
});

app.listen(port, () => console.log('Started server on port ' + port));

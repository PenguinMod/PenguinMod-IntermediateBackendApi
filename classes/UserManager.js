const Database = require("../easy-json-database");
const { default: axios } = require("axios");

const { randomUUID } = require("crypto");
const { encrypt, decrypt } = require("../utilities/encrypt.js");
const { ParseJSON } = require("../utilities/safejsonparse.js");
const Cast = require("./Cast.js");

const ScratchAuthURLs = {
    verifyToken: `https://auth-api.itinerary.eu.org/auth/verifyToken/`,
    verifyOAuth2: `https://oauth2.scratch-wiki.info/w/rest.php/soa2/v0/tokens`,
    getOAuth2Name: `https://oauth2.scratch-wiki.info/w/rest.php/soa2/v0/user`,
};

const generateId = () => {
    const rn = [
        Math.random() * 100000,
        Math.random() * 100000,
        Math.random() * 100000,
        Math.random() * 100000
    ];
    const raw = rn.join('.');
    return Buffer.from(raw).toString("base64");
};
const generateOAuth2State = () => {
    const uuid = randomUUID();
    const state = `pm-${uuid}`;
    return state;
};

const userLoginDB = new Database(`./users.json`);
const loginStates = {
    ips: {}, // { '127.0.0.1': { valid: true, expire: Date.now() } }
    states: {}
};
class UserManager {
    static createBaseIfNotPresent() {
        const sessions = userLoginDB.get('sessions');
        const manual = userLoginDB.get('manual');

        // logged in users
        if (!sessions || typeof sessions !== 'object') {
            userLoginDB.set('sessions', {});
        }
        // manually added users
        if (!manual || typeof manual !== 'object') {
            userLoginDB.set('manual', {});
        }
    }
    static stateDateExpired(date) {
        const currentDate = Date.now();
        const maxTime = 60 * 5 * 1000; // 5 minutes
        return (currentDate - date) >= maxTime;
    }
    static invalidateOldIpStates() {
        for (const ip in loginStates.ips) {
            const ipState = loginStates.ips[ip];
            if (!ipState.valid || UserManager.stateDateExpired(ipState.expire)) {
                delete loginStates.ips[ip];
            }
        }
    }
    static requestOAuth2State(ip) {
        UserManager.invalidateOldIpStates();
        const ipState = loginStates.ips[ip];
        if (ipState) {
            delete loginStates.ips[ip];
        }

        const generatedState = generateOAuth2State();
        const maxTime = 60 * 5 * 1000; // 5 minutes
        loginStates.states[generatedState] = {
            valid: true,
            expire: Date.now() + maxTime,
            ip
        };
        loginStates.ips[ip] = {
            valid: true,
            expire: Date.now() + maxTime
        }

        return generatedState;
    }
    static invalidateOAuth2State(state) {
        const loginState = loginStates.states[state];
        if (!loginState) return;

        const ip = loginState.ip;
        if (ip in loginStates.ips) {
            delete loginStates.ips[ip];
        }

        delete loginStates.states[state];
    }

    static isCorrectCode(username, privateCode) {
        const sessions = userLoginDB.get('sessions');
        const manual = userLoginDB.get('manual');
        
        // check if our private code is in sessions or manual sessions
        const instance = sessions[username] || manual[username];
        if (!instance) return false;

        // is the private code that we found correct?
        return instance === privateCode;
    }
    static usernameFromCode(privateCode) {
        const sessions = userLoginDB.get('sessions');
        const manual = userLoginDB.get('manual');
        const allLogins = {
            ...sessions,
            ...manual
        };
        
        return Object.keys(allLogins)
            .find(key => allLogins[key] === privateCode);
    }
    static async verifyCode(privateCode, state, ip) {
        const loginState = loginStates.states[state] || {};
        if (loginState.valid !== true) {
            throw new Error('The login process has expired');
        }
        if (loginState.ip !== ip) {
            throw new Error('Logins must start and end on the same IP address');
        }
        UserManager.invalidateOAuth2State(state);

        const response = await axios({
            url: ScratchAuthURLs.verifyOAuth2,
            method: 'post',
            data: {
                client_id: Cast.toNumber(process.env.ScratchOAuth2ClientId),
                client_secret: process.env.ScratchOAuth2ClientSecret,
                code: privateCode,
                scopes: ["identify"]
            }
        });
        if (!response) {
            throw new Error('No response object');
        }
        if (!response.data) {
            throw new Error('No data attached with response');
        }

        const accessToken = response.data.access_token;
        if (!accessToken) {
            throw new Error('No access_token attached with response data');
        }
        if (typeof accessToken !== 'string') {
            throw new Error('access_token is not string');
        }

        const base64 = Buffer.from(accessToken).toString('base64');
        const responseUser = await axios.get(ScratchAuthURLs.getOAuth2Name, {
            headers: { 'Authorization': `Bearer ${base64}` }
        });
        if (!responseUser) {
            throw new Error('No response object from OAuth2 name request');
        }
        if (!responseUser.data) {
            throw new Error('No data attached with OAuth2 name response');
        }

        const username = responseUser.data.user_name;
        if (!username || typeof username !== 'string') {
            throw new Error('No valid username attached with OAuth2 name response');
        }
        
        return username;
    }

    static setCode(username, privateCode, manual) {
        const loginDB = manual ? 'manual' : 'sessions';
        const sessions = userLoginDB.get(loginDB);

        sessions[username] = privateCode;
        userLoginDB.set(loginDB, sessions);
    }
    static logoutUser(username) {
        const sessions = userLoginDB.get('sessions');
        const manual = userLoginDB.get('manual');

        let changedSessions = false;
        let changedManual = false;
        if (username in sessions) {
            changedSessions = true;
            delete sessions[username];
        }
        if (username in manual) {
            changedManual = true;
            delete manual[username];
        }

        if (changedSessions) userLoginDB.set('sessions', sessions);
        if (changedManual) userLoginDB.set('manual', manual);
    }

    // banned users
    static isBanned(username) {
        const db = new Database(`./banned.json`);
        if (db.get(String(username))) return true;
        return false;
    }
    static ban(username, reason) {
        const db = new Database(`./banned.json`);
        db.set(String(username), String(reason));
    }
    static unban(username) {
        const db = new Database(`./banned.json`);
        db.delete(String(username));
    }

    // messages
    static getMessages(username) {
        const db = new Database(`./usermessages.json`);
        const messages = db.get(username);
        if (!messages) {
            return [];
        }
        return messages;
    }
    static getUnreadMessages(username) {
        const db = new Database(`./usermessages.json`);
        const messages = db.get(username);
        if (!messages) {
            return [];
        }
        return messages.filter(message => !message.read);
    }
    static getReports(username) {
        const db = new Database(`./userreports.json`);
        const reports = db.get(username);
        if (!Array.isArray(reports)) {
            return [];
        }
        return reports
    }
    static getAllReports() {
        const db = new Database(`./userreports.json`);
        return db.all();
    }
    static addReport(username, report, checkForTooMany) {
        const db = new Database(`./userreports.json`);
        const reports = UserManager.getReports(username);
        reports.unshift(report);
        db.set(username, reports);
        if (checkForTooMany) {
            // if the reporter has reported more than 3 times, add a report to them
            UserManager.punishSameUserReports(reports, report.reporter, username);
        }
    }
    static punishSameUserReports(reports, reporter, originalTarget) {
        // if the reporter has reported more than 3 times, add a report to them
        const reportsByUser = reports.filter(r => r.reporter === reporter);
        if (reportsByUser.length >= 3) {
            // note originalTarget can be a string with "Project (project id)"
            console.log(reporter, "reported", originalTarget, "too many times");
            const id = `repu-${Date.now()}-server-${Math.random()}`;
            UserManager.addReport(reporter, {
                reason: `Reported ${originalTarget} ${reportsByUser.length} times with pending reports`,
                reporter: "Projects API", // this is an invalid username, so it cant be taken
                id
            }, false); // dont check "Projects API" if they have too many reports given
        }
    }
    static addMessage(username, message, local) {
        const db = new Database(`./usermessages.json`);
        const messages = db.get(username);
        const newmessage = {
            ...message,
            id: generateId()
        };
        if (!messages) {
            db.set(username, [
                newmessage
            ]);
            return;
        }
        messages.unshift(newmessage);
        if (local) {
            db.setLocal(username, messages);
        } else {
            db.set(username, messages);
        }
    }
    static applyMessages() {
        const db = new Database(`./usermessages.json`);
        db.saveDataToFile();
    }
    static addModeratorMessage(username, message) {
        return UserManager.addMessage(username, {
            ...message,
            moderator: true
        });
    }
    static modifyMessage(username, id, modifierFunction) {
        const db = new Database(`./usermessages.json`);
        const messages = db.get(username);
        if (!messages) {
            return;
        }
        const message = messages.filter(message => message.id === id)[0];
        if (!message) {
            return;
        }
        const newMessage = modifierFunction(message);
        let idx = 0;
        for (const message of messages) {
            if (message.id === id) {
                break;
            }
            idx++;
        }
        messages[idx] = newMessage;
        db.set(username, messages);
    }
    static deleteMessage(username, id) {
        const db = new Database(`./usermessages.json`);
        const messages = db.get(username);
        if (!messages) {
            return;
        }
        db.set(username, messages.filter(message => message.id !== id));
    }
    static getRawMessageData() {
        const db = new Database(`./usermessages.json`);
        const all = db.all();
        const object = {};
        for (const piece of all) {
            object[piece.key] = piece.data;
        }
        return object;
    }
    static markMessagesAsRead(username) {
        const db = new Database(`./usermessages.json`);
        const messages = db.get(username);
        if (!messages) {
            return;
        }
        db.set(username, messages.map(message => ({
            ...message,
            read: true
        })));
    }

    static getProperty(username, property) {
        const db = new Database(`./userdata.json`);
        const userdata = db.get(username);
        if (!userdata) {
            return;
        }
        return userdata[property];
    }
    static setProperty(username, property, value) {
        const db = new Database(`./userdata.json`);
        const userdata = db.get(username);
        if (!userdata) {
            db.set(username, {
                [property]: value
            });
            return;
        }
        db.set(username, {
            ...userdata,
            [property]: value
        });
    }

    static getFollowers(username) {
        const db = new Database(`./following.json`);
        const followerList = db.get(username);
        if (!followerList) {
            return [];
        }
        if (!Array.isArray(followerList)) {
            return [];
        }
        return followerList;
    }
    static setFollowers(username, newArray) {
        const db = new Database(`./following.json`);
        if (!Array.isArray(newArray)) {
            console.error("Cannot set", username, "followers to non array");
            return;
        }
        db.set(username, newArray);
    }
    static getHadFollowers(username) {
        const db = new Database(`./hadfollowing.json`);
        return (db.get(username) ?? []);
    }
    static setHadFollower(username, follower) {
        const db = new Database(`./hadfollowing.json`);
        const followerList = db.get(username) ?? [];
        if (!followerList.includes(follower)) {
            followerList.push(follower);
            db.set(username, followerList);
        }
    }
    static addFollower(username, follower) {
        const followers = UserManager.getFollowers(username);
        if (followers.includes(follower)) return;
        followers.push(follower);
        UserManager.setFollowers(username, followers);
        UserManager.setHadFollower(username, follower);
    }
    static removeFollower(username, follower) {
        const followers = UserManager.getFollowers(username);
        if (!followers.includes(follower)) return;
        const idx = followers.indexOf(follower);
        if (idx === -1) return;
        followers.splice(idx, 1);
        UserManager.setFollowers(username, followers);
    }
    static notifyFollowers(username, feedMessage) {
        const db = new Database(`./userfeed.json`);
        const followers = UserManager.getFollowers(username);
        for (const follower of followers) {
            UserManager.addToUserFeed(follower, feedMessage, true);
        }
        db.saveDataToFile();
    }

    static getUserFeed(username) {
        const db = new Database(`./userfeed.json`);
        const userfeed = db.get(username);
        if (!Array.isArray(userfeed)) {
            return [];
        }
        return userfeed;
    }
    static setUserFeed(username, data, local) {
        const db = new Database(`./userfeed.json`);
        if (!Array.isArray(data)) {
            console.error("Cannot set", username, "feed to non-array");
            return;
        }
        if (local) {
            db.setLocal(username, data);
            return;
        }
        db.set(username, data);
    }
    static addToUserFeed(username, message, local) {
        const feed = UserManager.getUserFeed(username);
        feed.unshift(message);
        // feed is not meant to be an infinite log
        UserManager.setUserFeed(username, feed.slice(0, 25), local);
    }
}

module.exports = UserManager;
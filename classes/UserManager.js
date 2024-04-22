const Database = require("../easy-json-database");

const { encrypt, decrypt } = require("../utilities/encrypt.js");
const { ParseJSON } = require("../utilities/safejsonparse.js");

const ScratchAuthURLs = {
    verifyToken: `https://auth-api.itinerary.eu.org/auth/verifyToken/`,
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

class UserManager {
    static _states = {}

    static async serialize() {
        const db = new Database(`./users.json`);
        db.set("data", encrypt(JSON.stringify(UserManager._states)));
    }
    static deserialize() {
        // todo: this data is not required for the api to run since clearing it just makes everyone have to log in again
        // so we should handle errors and just reset the DB if it failed to deserialize
        const db = new Database(`./users.json`);
        if (!db.get("data")) return {};
        return ParseJSON(decrypt(db.get("data")));
    }

    static load() {
        UserManager._states = UserManager.deserialize();
    }

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

    static isCorrectCode(username, privateCode) {
        if (!privateCode) return false;
        if (!UserManager._states[username]) return false;
        if (typeof UserManager._states[username] !== 'string') return false;
        return UserManager._states[username] == privateCode;
    }
    static usernameFromCode(privateCode) {
        const codes = Object.getOwnPropertyNames(UserManager._states);
        let returning = null;
        for (let i = 0; i < codes.length; i++) {
            if (UserManager._states[codes[i]] == privateCode) {
                returning = codes[i];
            }
        }
        return returning;
    }
    static setCode(username, privateCode) {
        UserManager._states[username] = privateCode;
        UserManager.serialize();
    }
    static logoutUser(username) {
        if (UserManager._states[username] == null) return;
        delete UserManager._states[username];
        UserManager.serialize();
    }
    static async verifyCode(privateCode) {
        const url = ScratchAuthURLs.verifyToken + privateCode;
        const res = await fetch(url);
        const json = await res.json();
        return json;
    }

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
        return reports;
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
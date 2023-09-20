const Database = require("easy-json-database");

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
    static verifyCode(privateCode) {
        return new Promise((resolve, reject) => {
            fetch(ScratchAuthURLs.verifyToken + privateCode).then(res => {
                res.json().then(resolve).catch(reject);
            }).catch(reject);
        });
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
    static addMessage(username, message) {
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
        db.set(username, messages);
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
}

module.exports = UserManager;
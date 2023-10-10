const Database = require("easy-json-database");
const UserManager = require("./classes/UserManager.js");
const Cast = require("./classes/Cast.js");

const db = new Database(`${__dirname}/projects/published.json`);

function approveProject(id) {
    // this was copied and edited from the approving end point
    if (!db.has(id)) {
        // not found
        return false;
    }

    // newMeta
    // replace
    let isUpdated = false;
    let isRemix = false;

    let idToSetTo = id;
    // idk if db uses a reference to the object or not
    const project = JSON.parse(JSON.stringify(db.get(id)));
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
    return true;
}

function approveAllProjects() {
    const projects = db.all().map(value => { return value.data });
    let approvedProjects = 0;
    for (let i = 0; i < projects.length; i++) {
        const project = projects[i];
        if (project.accepted) continue;
        if (project.hidden) return console.log(id, 'is hidden, skipping');
        if (approveProject(Cast.toString(project.id))) {
            approvedProjects++;
        }
    }
    // post log
    const body = JSON.stringify({
        content: `${approvedProjects} were approved by Server`,
        embeds: [{
            title: `${approvedProjects} were approved`,
            color: 0x00ff00,
            fields: [
                {
                    name: "Approved by",
                    value: 'Server'
                }
            ],
            timestamp: new Date().toISOString()
        }]
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
    });
}

approveAllProjects();
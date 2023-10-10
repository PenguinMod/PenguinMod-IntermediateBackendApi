const Database = require("easy-json-database");
const UserManager = require("./classes/UserManager.js");
UserManager.load();

function approveProject(id) {
    
    // this was copied and edited from the approving end point

    const db = new Database(`${__dirname}/projects/published.json`);
    if (!db.has(packet.id)) {
        // not found
        return;
    }

    // newMeta
    // replace
    let isUpdated = false;
    let isRemix = false;

    let idToSetTo = id
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
}

function approveAllProjects() {
    const projects = db.all().map(value => { return value.data })
    for (let i = 0; i < projects.length; i++) {
        const project = projects[i];
        if (project.accepted) continue;
        approveProject(project.id);
    }

    // send log webhook
    const body = JSON.stringify({
        content: `All projects were approved by Admins`
    });
    fetch(process.env.ApproverLogWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(JSON.parse(body))
    });
}
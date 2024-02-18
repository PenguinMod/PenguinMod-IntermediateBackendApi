class QuickLog {
    static send(title, info, color) {
        const body = JSON.stringify({
            embeds: [{
                title: title || 'Website Log',
                color: color || 0xffbb00,
                description: `${info}`,
                timestamp: new Date().toISOString()
            }]
        });
        fetch(process.env.ApproverLogWebhook, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body
        });
    }
}

module.exports = QuickLog;
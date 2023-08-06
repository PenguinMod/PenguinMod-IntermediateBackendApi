const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const app = express();
const port = 8080;

app.use(cors({
    origin: '*',
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) die on 204
}));
app.use(bodyParser.urlencoded({
    limit: "1kb",
    extended: false
}));
app.use(bodyParser.json({ limit: "1kb" }));

app.get('/', async function (_, res) {
    res.status(200);
    res.header("Content-Type", 'text/html');
    res.sendFile(path.join(__dirname, "test.html"));
});
app.get('/folder', async function (_, res) {
    res.status(200);
    res.header("Content-Type", 'text/html');
    res.sendFile(path.join(__dirname, "/folder/test.html"));
});
app.get('/json', async function (_, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json({ "test": true });
});
app.get('/query', async function (req, res) {
    res.status(200);
    res.header("Content-Type", 'application/json');
    res.json(req.query);
});

app.listen(port, () => console.log('Started server on port ' + port));

require('dotenv').config();
const express = require('express');
const errsoleMongoModule = require('./MongoModule/mongo'); 
const app = express();
const port = 3000;

const url = process.env.MONGODB_URL;
const dbName = process.env.MONGODB_DB; 
// Connect to MongoDB
errsoleMongoModule.connectionToMongoDB(url, dbName).catch(err => {
    console.error('Failed to connect to MongoDB:', err);
});

app.use(async (req, res, next) => {
    const logData = { message: `Accessing ${req.path}` };
    await errsoleMongoModule.saveInfoLogs(logData);
    await errsoleMongoModule.saveErrorLogs(logData); 
    next();
});

app.get('/logs', async (req, res) => {
    try {
        const logs = await errsoleMongoModule.getLogs();
        res.json(logs);
    } catch (error) {
        console.error('Error fetching logs', error);
        res.status(500).send('Error fetching logs');
    }
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});

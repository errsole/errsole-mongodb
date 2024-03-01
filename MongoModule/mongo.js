const { MongoClient } = require('mongodb');
const CollectionName = 'Logs';
var client;
var DBName;

async function connectionToMongoDB(url, dbName) {
    try {
        DBName = dbName;
        client = new MongoClient(url);
        await client.connect();
        console.log('Connected to MongoDB');
        const db = client.db(DBName);
        const collections = await db.listCollections({ name: CollectionName }).toArray();
        if (collections.length === 0) {
            await db.createCollection(CollectionName);
        }
    } catch (err) {
        console.error('Error connecting to MongoDB', err);
        throw err;
    }
}

async function saveErrorLogs(logData) {
    const logEntry = { level: 'error', ...logData, timestamp: new Date().getTime() };
    await saveLogs(logEntry);
}

async function saveInfoLogs(logData) {
    const logEntry = { level: 'info', ...logData, timestamp: new Date().getTime() };
    await saveLogs(logEntry);
}

async function saveLogs(logEntry) {
    try {
        const db = client.db(DBName);
        const collection = db.collection(CollectionName);
        await collection.insertOne(logEntry);
    } catch (err) {
        console.error('Failed to save logs', err);
        throw err; 
    }
}

async function getLogs() {
    try {
        const db = client.db(DBName);
        const collection = db.collection(CollectionName);
        return await collection.find({}).toArray();
    } catch (err) {
        console.error('Failed to get logs', err);
        throw err; 
    }
}


module.exports = {
    connectionToMongoDB,
    saveErrorLogs,
    saveInfoLogs,
    getLogs, 
    
};

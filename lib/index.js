const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

class ErrsoleMongoDB {
    constructor(uri, dbName) {
        this.uri = uri;
        this.dbName = dbName;
        this.client = new MongoClient(this.uri);
        this.db = null;
        this.logsCollectionName = 'errsole-logs';
        this.usersCollectionName = 'errsole-users';
        this.isConnecting = false;
        this.init();
    }

     async init() {
        try {
            await this.client.connect();
            this.db = this.client.db(this.dbName);
             console.log('Successfully connected to MongoDB');
             await this.ensureCollections();
        } catch (error) {
            console.error('Failed to connect to MongoDB:', error);
            throw error;
        }finally{
            this.isConnecting = false;
        }

    }

    async ensureCollections() {
        const collections = await this.db.listCollections({}, { nameOnly: true }).toArray();
        const collectionNames = collections.map(col => col.name);

        if (!collectionNames.includes(this.logsCollectionName)) {
            await this.db.createCollection(this.logsCollectionName);
            await this.db.collection(this.logsCollectionName).createIndex({ timestamp: 1, level: 1 });
        }

        if (!collectionNames.includes(this.usersCollectionName)) {
            await this.db.createCollection(this.usersCollectionName);
        }
    }

    async postLogs(logEntries) {
        while (this.isConnecting || !this.db) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        if (!Array.isArray(logEntries)) {
            logEntries = [logEntries];
        }
        try{
            const result = await this.db.collection(this.logsCollectionName).insertMany(logEntries);
            return result;
        }catch{
            throw new Error('Failed to post logs');
        }

    }

    async getLogs(filters) {
        const query = {};
        if (filters.level) {
            query.level = filters.level;
        }
        if (filters.lte) {
            query.timestamp = { ...query.timestamp, $lte: new Date(filters.lte) };
        }
        if (filters.gte) {
            query.timestamp = { ...query.timestamp, $gte: new Date(filters.gte) };
        }

        return await this.db.collection(this.logsCollectionName)
                             .find(query)
                             .sort({ timestamp: -1 })
                             .limit(filters.limit || 50)
                             .toArray();
    }

    async createUser(user) {
        if (!user.email || !user.password) {
            throw new Error('User email and password are required');
        }
        const hashedPassword = await bcrypt.hash(user.password, 10);
        return await this.db.collection(this.usersCollectionName).insertOne({
            ...user,
            password: hashedPassword
        });
    }

    async verifyUser({ email, password }) {
        if (!email || !password) {
            throw new Error('Email and password are required for verification');
        }
        const user = await this.db.collection(this.usersCollectionName).findOne({ email: email });
        if (!user) {
            throw new Error('User not found');
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            throw new Error('Password does not match');
        }
        return { ...user, password: undefined };
    }
}
module.exports = ErrsoleMongoDB;

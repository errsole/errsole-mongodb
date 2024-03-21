const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');

class ErrsoleMongoDB {
  constructor (uri, dbName) {
    this.uri = uri;
    this.dbName = dbName;
    this.client = new MongoClient(this.uri);
    this.db = null;
    this.logsCollectionName = 'errsole-logs';
    this.usersCollectionName = 'errsole-users';
    this.isConnectionInProgress = true;
    this.init();
  }

  async init () {
    try {
      await this.client.connect();
      this.db = this.client.db(this.dbName);
      console.log('Successfully connected to MongoDB');
      await this.ensureCollections();
    } catch (error) {
      console.error('Failed to connect to MongoDB:', error);
      throw error;
    } finally {
      this.isConnectionInProgress = false;
    }
  }

  async ensureCollections () {
    const collections = await this.db.listCollections({}, { nameOnly: true }).toArray();
    const collectionNames = collections.map(col => col.name);

    if (!collectionNames.includes(this.logsCollectionName)) {
      await this.db.createCollection(this.logsCollectionName);
      await this.db.collection(this.logsCollectionName).createIndex({ timestamp: 1, level: 1 });
    }

    if (!collectionNames.includes(this.usersCollectionName)) {
      await this.db.createCollection(this.usersCollectionName);
      await this.db.collection(this.usersCollectionName).createIndex({ email: 1 }, { unique: true });
    }
  }

  async postLogs (logEntries) {
    while (this.isConnectionInProgress || !this.db) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!Array.isArray(logEntries)) {
      logEntries = [logEntries];
    }
    try {
      const result = await this.db.collection(this.logsCollectionName).insertMany(logEntries);
      return result;
    } catch {
      throw new Error('Failed to post logs');
    }
  }

  async getLogs (filters) {
    try {
      let query = {};   
      let sortby = -1;
      if (filters) {
        if (filters.start_datetime && filters.sort_by) {
          if (filters.sort_by === 'asc') {
            sortby = 1;
            query = { timestamp: { $gte: filters.start_datetime } };
          } else if (filters.sort_by === 'desc') {
            sortby = -1;
            query = { timestamp: { $lte: filters.start_datetime } };
          }
          if (filters.previous_log_id) {
            query._id = {};
            query._id.$ne = new ObjectId(filters.previous_log_id);
          }
        } else {
          query = { timestamp: { $gte: new Date().toISOString() } };
        }
        if (filters.level) {
          query.level = filters.level;
        }
      }

      // Executing query
      const documents = await this.db.collection(this.logsCollectionName)
        .find(query)
        .sort({ timestamp: sortby })
        .limit(filters.limit || 50)
        .toArray();

      // Renaming _id to logId and converting to plain objects if necessary
      const modifiedDocuments = documents.map(doc => { const { _id, ...rest } = doc; return { id: _id, ...rest }; });
      return modifiedDocuments;
    } catch (err) {
      console.error('Error in getLogs:', err);
      throw err; // Rethrowing the error or handling it as needed
    }
  }

  async createUser (user) {
    if (!user.email || !user.password) {
      throw new Error('User email and password are required');
    }
    const hashedPassword = await bcrypt.hash(user.password, 10);
    try {
      const result = await this.db.collection(this.usersCollectionName).insertOne({
        ...user,
        password: hashedPassword
      });
      return result;
    } catch (error) {
      if (error.code === 11000) {
        throw new Error('Email already exists');
      }
      throw error;
    }
  }

  async verifyUser ({ email, password }) {
    if (!email || !password) {
      throw new Error('Email and password are required for verification');
    }
    const user = await this.db.collection(this.usersCollectionName).findOne({ email });
    if (!user) {
      throw new Error('User not found');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new Error('Password does not match');
    }
    return { ...user, password: undefined };
  }

  async getNumberOfUsers(){
    try {
      const result = await this.db.collection(this.usersCollectionName).countDocuments({});
      return result;
    }catch (error) {
      throw error;
    }
  }
  
}
module.exports = ErrsoleMongoDB;

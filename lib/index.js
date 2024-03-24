const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const saltRounds = 10;

class ErrsoleMongoDB {
  constructor (uri, dbName) {
    this.uri = uri;
    this.dbName = dbName;
    this.client = new MongoClient(this.uri);
    this.db = null;
    this.logsCollectionName = 'errsole-logs';
    this.usersCollectionName = 'errsole-users';
    this.configCollectionName = 'errsole-config';
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
    if (!collectionNames.includes(this.configCollectionName)) {
      await this.db.createCollection(this.configCollectionName);
      await this.db.collection(this.configCollectionName).createIndex({ name: 1 }, { unique: true });
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
      return { status: false, error: 'User email and password required' };
    }
    try {
      const hashedPassword = await bcrypt.hash(user.password, saltRounds);
      const result = await this.db.collection(this.usersCollectionName).insertOne({
        ...user,
        password: hashedPassword
      });
      if (result.insertedId) {
        return { status: true, action: 'created' };
      } else {
        return { status: false, error: 'User could not be created' };
      }
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
      throw new Error('Email not found');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new Error('Password does not match');
    }
    return { ...user, password: undefined };
  }

  async getNumberOfUsers () {
    const result = await this.db.collection(this.usersCollectionName).countDocuments({});
    return result;
  }

  async getConfig (name) {
    try {
      const result = await this.db.collection(this.configCollectionName).findOne({ name });
      return result ? result.value : null;
    } catch (error) {
      console.error('Error retrieving configuration:', error);
      throw error;
    }
  }

  async setConfig (name, value) {
    try {
      const result = await this.db.collection(this.configCollectionName).updateOne(
        { name },
        { $set: { value } },
        { upsert: true }
      );

      if (result.upsertedCount > 0) {
        return { status: true, action: 'created' };
      } else {
        return { status: false, error: 'No operation was performed' };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async getUserProfile (email) {
    if (!email) {
      return { status: false, error: 'Email is required' };
    }
    try {
      const user = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { password: 0 } });
      if (user) {
        user.id = user._id;
        delete user._id;
        return { status: true, userProfile: user };
      } else {
        return { status: false, error: 'User not found' };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async updateUserProfile (email, updates) {
    if (!email) {
      return { status: false, error: 'Email is required' };
    }
    if (!updates || Object.keys(updates).length === 0) {
      return { status: false, error: 'No updates provided' };
    }
    delete updates.password;
    delete updates.id;
    try {
      const updateResult = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: updates });
      if (updateResult.matchedCount === 0) {
        return { status: false, error: 'User not found' };
      }
      if (updateResult.modifiedCount === 0) {
        return { status: false, error: 'No updates applied' };
      }
      return { status: true, message: 'User profile updated successfully' };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async updatePassword (email, currentPassword, newPassword) {
    if (!email || !currentPassword || !newPassword) {
      return { status: false, error: 'Email, current password, and new password are required' };
    }

    try {
      const user = await this.db.collection(this.usersCollectionName).findOne({ email });
      if (!user) {
        return { status: false, error: 'User not found' };
      }

      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return { status: false, error: 'Current password is incorrect' };
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

      const updateResult = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: { password: hashedNewPassword } });
      if (updateResult.modifiedCount === 0) {
        return { status: false, error: 'Password update failed' };
      }

      return { status: true, message: 'Password updated successfully' };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }
}

module.exports = ErrsoleMongoDB;

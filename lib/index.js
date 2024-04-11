/**
 * @typedef {Object} Log
 * @property {number | string} [id]
 * @property {string} [source=console]
 * @property {Date} timestamp
 * @property {string} level
 * @property {string} message
 * @property {string} [meta]
 * @property {string} [public_ip]
 * @property {string} [private_ip]
 */

/**
 * @typedef {Object} LogFilter
 * @property {string} [source]
 * @property {number | string} [lt_id]
 * @property {number | string} [gt_id]
 * @property {Date} [lte_timestamp]
 * @property {Date} [gte_timestamp]
 * @property {string} [level]
 * @property {string} [public_ip]
 * @property {string} [private_ip]
 * @property {number} [limit=100]
 */

/**
 * @typedef {Object} User
 * @property {number | string} id
 * @property {string} name
 * @property {string} email
 * @property {string} role
 */

/**
 * @typedef {Object} Config
 * @property {number | string} id
 * @property {string} name
 * @property {string} value
 */

const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');

const saltRounds = 10;

class ErrsoleMongoDB {
  constructor (...args) {
    this.uri = args[0];
    this.connectionOptions = {};
    if (typeof args[1] === 'string') {
      this.dbName = args[1];
    } else if (typeof args[1] === 'object') {
      this.connectionOptions = args[1];
    }
    if (typeof args[2] === 'object') {
      this.connectionOptions = args[2];
    }
    this.client = new MongoClient(this.uri, this.connectionOptions);
    this.logsCollectionName = 'errsole-logs';
    this.usersCollectionName = 'errsole-users';
    this.configCollectionName = 'errsole-config';
    this.isConnectionInProgress = true;
    this.init();
  }

  async init () {
    await this.client.connect();
    this.db = this.client.db(this.dbName);
    await this.ensureCollections();
    this.isConnectionInProgress = false;
  }

  async ensureCollections () {
    await this.db.createCollection(this.logsCollectionName);
    await this.db.collection(this.logsCollectionName).createIndex({ timestamp: 1, level: 1 });
    await this.db.collection(this.logsCollectionName).createIndex({ message: 'text' });
    await this.db.createCollection(this.usersCollectionName);
    await this.db.collection(this.usersCollectionName).createIndex({ email: 1 }, { unique: true });
    await this.db.createCollection(this.configCollectionName);
    await this.db.collection(this.configCollectionName).createIndex({ name: 1 }, { unique: true });
  }

  /**
   * Add log entries to the database.
   *
   * @async
   * @function postLogs
   * @param {Log[]} logEntries
   * @return {Promise<{}>}
   */
  async postLogs (logEntries) {
    while (this.isConnectionInProgress) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    await this.db.collection(this.logsCollectionName).insertMany(logEntries);
    return {};
  }

  /**
   * Get log entries from the database based on specified filtering criteria.
   *
   * @async
   * @function getLogs
   * @param {LogFilter} filters
   * @returns {Promise<{items: Log[]}>}
   */
  async getLogs (filters) {
    const query = {};
    if (filters) {
      if (filters.lte) {
        query.timestamp = { $lte: filters.lte };
      }
      if (filters.get) {
        query.get = filters.get;
      }
      if (filters.level) {
        query.level = filters.level;
      }
    }
    const documents = await this.db.collection(this.logsCollectionName)
      .find(query)
      .sort({ timestamp: -1 })
      .limit(filters.limit || 50)
      .toArray();

    // Renaming _id to logId and converting to plain objects if necessary
    const modifiedDocuments = documents.map(doc => { const { _id, ...rest } = doc; return { id: _id, ...rest }; });
    return { items: modifiedDocuments };
  }

  /**
   * Get log entries from the database based on specified search and filtering criteria.
   *
   * @async
   * @function searchLogs
   * @param {string[]} search_terms
   * @param {LogFilter} [filters]
   * @returns {Promise<{items: Log[]}>}
   */
  async searchLogs (searchTerm) {
    try {
      const results = await this.db.collection(this.logsCollectionName).find({
        $text: { $search: searchTerm }
      }, {
        projection: { message: 1, timestamp: 1, level: 1 } // Removed score projection
      }).sort({ timestamp: -1 }).toArray(); // Sort by timestamp, descending order

      return results.map(result => {
        return { ...result };
      });
    } catch (error) {
      console.error('Error searching logs:', error);
      throw error;
    }
  }

  /**
   * Create a new user record in the database.
   *
   * @async
   * @function createUser
   * @param {Object} user
   * @param {string} user.name
   * @param {string} user.email
   * @param {string} user.password
   * @param {string} user.role
   * @returns {Promise<{item: User}>}
   */
  async createUser (user) {
    if (!user.email || !user.password) {
      throw new Error('User email and password required');
    }
    const hashedPassword = await bcrypt.hash(user.password, saltRounds);
    const result = await this.db.collection(this.usersCollectionName).insertOne({
      ...user,
      password: hashedPassword
    });
    if (result.insertedId) {
      delete user.password;
      return { item: user };
    } else {
      throw new Error('User could not be created');
    }
  }

  /**
   * Verify a user's email and password.
   *
   * @async
   * @function verifyUser
   * @param {string} email
   * @param {string} password
   * @returns {Promise<{item: User}>}
   */
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
    user.password = undefined;
    return { item: user };
  }

  /**
   * Get the total number of users stored in the database.
   *
   * @async
   * @function getUserCount
   * @returns {Promise<{count: number}>}
   */
  async getUserCount () {
    const count = await this.db.collection(this.usersCollectionName).countDocuments({});
    return { count };
  }

  /**
   * Get all user records from the database.
   *
   * @async
   * @function getAllUsers
   * @returns {Promise<{items: User[]}>}
   */
  async getAllUsers () {
    const users = await this.db.collection(this.usersCollectionName).find({}, { projection: { password: 0 } }).toArray();
    const usersWithFormattedIds = users.map(dbUser => {
      const userWithFormattedId = { ...dbUser, id: dbUser._id };
      delete userWithFormattedId._id;
      return userWithFormattedId;
    });
    return { items: usersWithFormattedIds };
  }

  /**
   * Get a configuration entry from the database.
   *
   * @async
   * @function getConfig
   * @param {string} name
   * @returns {Promise<{item: Config}>}
   */
  async getConfig (name) {
    const result = await this.db.collection(this.configCollectionName).findOne({ name });
    if (result && result._id) {
      result.id = result._id;
      delete result._id;
    }
    return { item: result };
  }

  /**
   * Store a configuration entry in the database.
   *
   * @async
   * @function setConfig
   * @param {string} name
   * @param {string} value
   * @returns {Promise<{item: Config}>}
   */
  async setConfig (name, value) {
    const result = await this.db.collection(this.configCollectionName).updateOne(
      { name },
      { $set: { value } },
      { upsert: true }
    );
    if (result.upsertedId) {
      return { item: { id: result.upsertedId, name, value } };
    } else {
      throw new Error('Error in set config');
    }
  }

  /**
   * Get a user record from the database.
   *
   * @async
   * @function getUser
   * @param {string} email
   * @returns {Promise<{item: User}>}
   */
  async getUserProfile (email) {
    if (!email) {
      throw new Error('Email is required');
    }
    const user = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { password: 0 } });
    if (user) {
      user.id = user._id;
      delete user._id;
      return { item: user };
    } else {
      throw new Error('User not found');
    }
  }

  /**
   * Update a user record in the database.
   *
   * @async
   * @function updateUser
   * @param {string} email
   * @param {Object} updates
   * @returns {Promise<{item: User}>}
   */
  async updateUserProfile (email, updates) {
    if (!email) {
      throw new Error('Email is required');
    }
    if (!updates || Object.keys(updates).length === 0) {
      throw new Error('No updates provided');
    }
    delete updates.password;
    delete updates.id;
    const updateResult = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: updates });
    if (updateResult.matchedCount === 0) {
      throw new Error('User not found');
    }
    if (updateResult.modifiedCount === 0) {
      throw new Error('No updates applied');
    }
    return { item: { email } };
  }

  /**
   * Update a user's password in the database.
   *
   * @async
   * @function updatePassword
   * @param {string} email
   * @param {string} currentPassword
   * @param {string} newPassword
   * @returns {Promise<{item: User}>}
   */
  async updatePassword (email, currentPassword, newPassword) {
    if (!email || !currentPassword || !newPassword) {
      throw new Error('Email, current password, and new password are required');
    }
    const user = await this.db.collection(this.usersCollectionName).findOne({ email });
    if (!user) {
      throw new Error('User not found');
    }
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      throw new Error('Current password is incorrect');
    }
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    const updateResult = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: { password: hashedNewPassword } });
    if (updateResult.modifiedCount === 0) {
      throw new Error('Password update failed');
    }
    return { item: { email } };
  }

  /**
   * Delete a user record from the database.
   *
   * @async
   * @function deleteUser
   * @param {string} userId
   * @returns {Promise<{}>}
   */
  async removeUser (userId) {
    if (!userId) {
      throw new Error('User ID is required');
    }
    const id = new ObjectId(userId);
    const deleteResult = await this.db.collection(this.usersCollectionName).deleteOne({ _id: id });
    if (deleteResult.deletedCount === 0) {
      throw new Error('User not found');
    }
    return { item: {} };
  }
}

module.exports = ErrsoleMongoDB;

/**
 * @typedef {Object} Log
 * @property {number | string} [id]
 * @property {string} [source=console]
 * @property {Date} [timestamp]
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
    const collections = await this.db.listCollections({}, { nameOnly: true }).toArray();
    const collectionNames = collections.map(collection => collection.name);
    if (!collectionNames.includes(this.logsCollectionName)) {
      await this.db.createCollection(this.logsCollectionName);
    }
    await this.db.collection(this.logsCollectionName).createIndex({ timestamp: 1, level: 1 });
    await this.db.collection(this.logsCollectionName).createIndex({ message: 'text' });
    if (!collectionNames.includes(this.usersCollectionName)) {
      await this.db.createCollection(this.usersCollectionName);
    }
    await this.db.collection(this.usersCollectionName).createIndex({ email: 1 }, { unique: true });
    if (!collectionNames.includes(this.configCollectionName)) {
      await this.db.createCollection(this.configCollectionName);
    }
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
   * @param {LogFilter} [filters]
   * @returns {Promise<{items: Log[]}>}
   */
  async getLogs (filters) {
    filters = filters || {};
    filters.limit = filters.limit || 100;
    const query = {};
    let sortby = { timestamp: -1 };
    let reverseDocuments = true;
    if (filters.lt_id) {
      query._id = { $lt: new ObjectId(filters.lt_id) };
      sortby = { _id: -1 };
    } else if (filters.gt_id) {
      query._id = { $gt: new ObjectId(filters.gt_id) };
      sortby = { _id: 1 };
      reverseDocuments = false;
    } else if (filters.lte_timestamp) {
      query.timestamp = { $lte: filters.lte_timestamp };
      sortby = { timestamp: -1 };
    } else if (filters.gte_timestamp) {
      query.timestamp = { $gte: filters.gte_timestamp };
      sortby = { timestamp: 1 };
      reverseDocuments = false;
    }
    if (filters.level) {
      query.level = filters.level;
    }
    const documents = await this.db.collection(this.logsCollectionName).find(query).sort(sortby).limit(filters.limit).toArray();
    if (reverseDocuments) {
      documents.reverse();
    }
    const formattedDocuments = documents.map(doc => {
      const { _id, ...rest } = doc;
      return { id: _id.toString(), ...rest };
    });
    return { items: formattedDocuments };
  }

  /**
   * Get log entries from the database based on specified search and filtering criteria.
   *
   * @async
   * @function searchLogs
   * @param {string[]} searchTerms
   * @param {LogFilter} [filters]
   * @returns {Promise<{items: Log[]}>}
   */
  async searchLogs (searchTerms, filters) {
    searchTerms = searchTerms.map(searchTerm => '"' + searchTerm + '"');
    filters = filters || {};
    filters.limit = filters.limit || 100;

    const query = {
      $text: { $search: searchTerms.join(' ') }
    };
    let sortby = { timestamp: -1 };
    let reverseDocuments = true;
    if (filters.lt_id) {
      query._id = { $lt: new ObjectId(filters.lt_id) };
      sortby = { _id: -1 };
    } else if (filters.gt_id) {
      query._id = { $gt: new ObjectId(filters.gt_id) };
      sortby = { _id: 1 };
      reverseDocuments = false;
    } else if (filters.lte_timestamp) {
      query.timestamp = { $lte: filters.lte_timestamp };
      sortby = { timestamp: -1 };
    } else if (filters.gte_timestamp) {
      query.timestamp = { $gte: filters.gte_timestamp };
      sortby = { timestamp: 1 };
      reverseDocuments = false;
    }
    if (filters.level) {
      query.level = filters.level;
    }

    const documents = await this.db.collection(this.logsCollectionName).find(query).sort(sortby).limit(filters.limit).toArray();
    if (reverseDocuments) {
      documents.reverse();
    }
    const formattedDocuments = documents.map(doc => {
      const { _id, ...rest } = doc;
      return { id: _id.toString(), ...rest };
    });
    return { items: formattedDocuments };
  }

  /**
   * Get a configuration entry from the database.
   *
   * @async
   * @function getConfig
   * @param {string} key
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
   * @param {string} key
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
      throw new Error('Failed to update configuration');
    }
  }

  /**
   * Creates a new user record in the database.
   *
   * @async
   * @function createUser
   * @param {Object} user - The user data.
   * @param {string} user.name - The name of the user.
   * @param {string} user.email - The email of the user.
   * @param {string} user.password - The password of the user.
   * @param {string} user.role - The role of the user.
   * @returns {Promise<{item: User}>} - A promise resolving to the created user item.
   * @throws {Error} - If the user record insertion fails or if a user with the same email already exists.
   */
  async createUser (user) {
    try {
      const hashedPassword = await bcrypt.hash(user.password, saltRounds);
      delete user.password;
      user.hashed_password = hashedPassword;
      const result = await this.db.collection(this.usersCollectionName).insertOne(user);
      if (result.insertedId) {
        const user = await this.db.collection(this.usersCollectionName).findOne({ _id: result.insertedId }, { projection: { hashed_password: 0 } });
        user.id = user._id.toString();
        delete user._id;
        return { item: user };
      } else {
        throw new Error('Failed to insert the user record into the database.');
      }
    } catch (err) {
      if (err.code === 11000) {
        throw new Error('A user with the provided email already exists.');
      }
      throw err;
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
  async verifyUser (email, password) {
    const user = await this.db.collection(this.usersCollectionName).findOne({ email });
    if (!user) {
      throw new Error('User not found.');
    }
    const match = await bcrypt.compare(password, user.hashed_password);
    if (!match) {
      throw new Error('Incorrect password.');
    }
    user.id = user._id.toString();
    delete user._id;
    delete user.hashed_password;
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
    let users = await this.db.collection(this.usersCollectionName).find({}, { projection: { hashed_password: 0 } }).toArray();
    users = users.map(user => {
      user.id = user._id.toString();
      delete user._id;
      return user;
    });
    return { items: users };
  }

  /**
   * Gets a user record from the database based on their email address.
   *
   * @async
   * @function getUserByEmail
   * @param {string} email - The email address of the user.
   * @returns {Promise<{item: User}>} - A promise resolving to an object containing the user record.
   * @throws {Error} Throws an error if the user with the provided email is not found.
   */
  async getUserByEmail (email) {
    const user = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { hashed_password: 0 } });
    if (user) {
      user.id = user._id.toString();
      delete user._id;
      return { item: user };
    } else {
      throw new Error('User not found.');
    }
  }

  /**
   * Updates a user record in the database using their email.
   *
   * @async
   * @function updateUserByEmail
   * @param {string} email - The email address of the user.
   * @param {Object} updates - The updates to apply to the user record.
   * @returns {Promise<{item: User}>} - A Promise that resolves to an object containing the updated user item.
   * @throws {Error} If no updates are applied because the user record was not found or the provided updates are identical to existing data.
   */
  async updateUserByEmail (email, updates) {
    delete updates.hashed_password;
    const result = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: updates });
    if (result.modifiedCount === 0) {
      throw new Error('No updates applied. User record not found or provided updates are identical to existing data.');
    }
    const user = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { hashed_password: 0 } });
    user.id = user._id.toString();
    delete user._id;
    return { item: user };
  }

  /**
   * Updates the password of a user in the database.
   *
   * @async
   * @function updatePassword
   * @param {string} email - The email address of the user.
   * @param {string} currentPassword - The current password of the user.
   * @param {string} newPassword - The new password to set for the user.
   * @returns {Promise<{item: User}>} - A Promise resolving to an object containing the user item.
   * @throws {Error} - Throws an error if the user is not found, current password is incorrect, or password update fails.
   */
  async updatePassword (email, currentPassword, newPassword) {
    const user = await this.db.collection(this.usersCollectionName).findOne({ email });
    if (!user) {
      throw new Error('User not found.');
    }
    const isMatch = await bcrypt.compare(currentPassword, user.hashed_password);
    if (!isMatch) {
      throw new Error('Current password is incorrect.');
    }
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    const result = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: { hashed_password: hashedNewPassword } });
    if (result.modifiedCount === 0) {
      throw new Error('Password update failed.');
    }
    user.id = user._id.toString();
    delete user._id;
    delete user.hashed_password;
    return { item: user };
  }

  /**
   * Deletes a user record from the database.
   *
   * @async
   * @function deleteUser
   * @param {string} id - The Id of the user to be deleted.
   * @returns {Promise<{}>} - A Promise that resolves to an empty object.
   * @throws {Error} - Throws an error if the user is not found.
   */
  async deleteUser (id) {
    const objectId = new ObjectId(id);
    const result = await this.db.collection(this.usersCollectionName).deleteOne({ _id: objectId });
    if (result.deletedCount === 0) {
      throw new Error('User not found.');
    }
    return {};
  }
}

module.exports = ErrsoleMongoDB;

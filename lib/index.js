/**
 * @typedef {Object} Log
 * @property {number} [id]
 * @property {number} [errsole_id]
 * @property {Date} timestamp
 * @property {string} hostname
 * @property {string} source
 * @property {string} level
 * @property {string} message
 * @property {string} [meta]
 */

/**
 * @typedef {Object} LogFilter
 * @property {number} [lt_id]
 * @property {number} [gt_id]
 * @property {number} [errsole_id]
 * @property {Date} [lte_timestamp]
 * @property {Date} [gte_timestamp]
 * @property {string[]} [hostnames]
 * @property {{source: string, level: string}[]} [level_json]
 * @property {number} [limit=100]
 */

/**
 * @typedef {Object} Config
 * @property {string} id
 * @property {string} name
 * @property {string} value
 */

/**
 * @typedef {Object} User
 * @property {string} id
 * @property {string} name
 * @property {string} email
 * @property {string} role
 */

/**
 * @typedef {Object} Notification
 * @property {number} [id]
 * @property {number} [errsole_id]
 * @property {string} hostname
 * @property {string} hashed_message
 * @property {Date} [created_at]
 * @property {Date} [updated_at]
 */

const bcrypt = require('bcryptjs');
const { EventEmitter } = require('events');
const { MongoClient, ObjectId } = require('mongodb');

const packageJSON = require('../package.json');
const saltRounds = 10;

class ErrsoleMongoDB extends EventEmitter {
  /**
   * Constructs an instance of the ErrsoleMongoDB.
   * @param {string} uri - MongoDB URI.
   * @param {string|Object} dbNameOrOptions - Database name as a string or connection options as an object.
   * @param {Object} [options] - Connection options if the second parameter is a database name.
   */
  constructor (uri, dbNameOrOptions, options = {}) {
    super();
    this.name = packageJSON.name;
    this.version = packageJSON.version || '0.0.0';

    this.uri = uri;
    this.dbName = typeof dbNameOrOptions === 'string' ? dbNameOrOptions : undefined;
    this.connectionOptions = typeof dbNameOrOptions === 'object' ? dbNameOrOptions : options;

    this.client = new MongoClient(this.uri, this.connectionOptions);
    this.logsCollectionName = 'errsole_logs';
    this.notificationsCollectionName = 'errsole_notifications';
    this.usersCollectionName = 'errsole_users';
    this.configCollectionName = 'errsole_config';
    this.isConnectionInProgress = true;
    this.pendingLogs = [];
    this.batchSize = 100;
    this.flushInterval = 1000;
    this.init();
  }

  async init () {
    await this.client.connect();
    this.db = this.client.db(this.dbName);
    await this.ensureCollections();
    this.isConnectionInProgress = false;
    this.emit('ready');
    setInterval(() => this.flushLogs(), this.flushInterval);
    await this.ensureLogsTTL();
  }

  async ensureCollections () {
    const collections = await this.db.listCollections({}, { nameOnly: true }).toArray();
    const collectionNames = collections.map(collection => collection.name);

    if (!collectionNames.includes(this.logsCollectionName)) {
      await this.db.createCollection(this.logsCollectionName);
    }

    await this.db.collection(this.logsCollectionName).createIndex({ source: 1, level: 1, _id: 1 });
    await this.db.collection(this.logsCollectionName).createIndex({ source: 1, level: 1, timestamp: 1 });
    await this.db.collection(this.logsCollectionName).createIndex({ hostname: 1, pid: 1, _id: 1 });
    await this.db.collection(this.logsCollectionName).createIndex({ message: 'text' });
    await this.db.collection(this.logsCollectionName).createIndex({ errsole_id: 1 });

    if (!collectionNames.includes(this.usersCollectionName)) {
      await this.db.createCollection(this.usersCollectionName);
    }
    await this.db.collection(this.usersCollectionName).createIndex({ email: 1 }, { unique: true });

    if (!collectionNames.includes(this.configCollectionName)) {
      await this.db.createCollection(this.configCollectionName);
    }
    try {
      await this.db.collection(this.configCollectionName).dropIndex('name_1');
    } catch {}
    await this.db.collection(this.configCollectionName).createIndex({ key: 1 }, { unique: true });

    if (!collectionNames.includes(this.notificationsCollectionName)) {
      await this.db.createCollection(this.notificationsCollectionName);
    }

    await this.db.collection(this.notificationsCollectionName).createIndex({ hostname: 1, hashed_message: 1, created_at: 1 });
    await this.db.collection(this.notificationsCollectionName).createIndex({ created_at: 1 });
  }

  /**
   * Retrieves a configuration entry from the database.
   *
   * @async
   * @function getConfig
   * @param {string} key - The key of the configuration entry to retrieve.
   * @returns {Promise<{item: Config}>} - A promise that resolves with an object containing the configuration item.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getConfig (key) {
    const result = await this.db.collection(this.configCollectionName).findOne({ key });

    if (!result) {
      return {};
    }

    const { _id, ...configDetails } = result;
    return { item: { id: _id.toString(), ...configDetails } };
  }

  /**
   * Updates or adds a configuration entry in the database.
   *
   * @async
   * @function setConfig
   * @param {string} key - The key of the configuration entry.
   * @param {string} value - The value to be stored for the configuration entry.
   * @returns {Promise<{item: Config}>} - A promise that resolves with an object containing the updated or added configuration item.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async setConfig (key, value) {
    const result = await this.db.collection(this.configCollectionName).updateOne(
      { key },
      { $set: { value } },
      { upsert: true }
    );

    if (result.matchedCount === 0 && result.upsertedCount === 0) {
      throw new Error('Failed to update or insert configuration.');
    }

    const savedItem = await this.db.collection(this.configCollectionName).findOne({ key });

    const { _id, ...rest } = savedItem;
    return { item: { id: _id.toString(), ...rest } };
  }

  /**
   * Deletes a configuration entry from the database.
   *
   * @async
   * @function deleteConfig
   * @param {string} key - The key of the configuration entry to be deleted.
   * @returns {Promise<{}>} - A Promise that resolves with an empty object upon successful deletion of the configuration.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async deleteConfig (key) {
    const result = await this.db.collection(this.configCollectionName).deleteOne({ key });
    if (result.deletedCount === 0) {
      throw new Error('Failed to delete configuration.');
    }
    return {};
  }

  /**
   * Adds log entries to the pending logs and flushes them if the batch size is reached.
   *
   * @param {Log[]} logEntries - An array of log entries to be added to the pending logs.
   * @returns {Object} - An empty object.
   */
  postLogs (logEntries) {
    this.pendingLogs.push(...logEntries);
    if (this.pendingLogs.length >= this.batchSize) {
      this.flushLogs();
    }
    return {};
  }

  /**
   * Flushes pending logs to the database.
   *
   * @async
   * @function flushLogs
   * @returns {Promise<{}>} - A Promise that resolves with an empty object.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async flushLogs () {
    while (this.isConnectionInProgress) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    const logsToPost = this.pendingLogs.splice(0, this.pendingLogs.length);
    if (logsToPost.length === 0) {
      return {};
    }
    try {
      await this.db.collection(this.logsCollectionName).insertMany(logsToPost);
      return {};
    } catch (err) {
      return err;
    }
  }

  /**
   * Retrieves unique hostnames from the database.
   *
   * @async
   * @function getHostnames
   * @returns {Promise<{items: string[]}>} - A Promise that resolves with an object containing an array of unique hostnames.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getHostnames () {
    try {
      const query = {
        hostname: { $nin: [null, ''] }
      };

      const hostnames = await this.db.collection(this.logsCollectionName).distinct('hostname', query);

      const filteredHostnames = hostnames.filter(Boolean).sort();
      return { items: filteredHostnames };
    } catch (err) {
      return err;
    }
  }

  /**
   * Retrieves log entries from the database based on specified filters.
   *
   * @async
   * @function getLogs
   * @param {LogFilter} [filters] - Filters to apply for log retrieval.
   * @returns {Promise<{items: Log[]}>} - A Promise that resolves with an object containing log items.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getLogs (filters = {}) {
    const defaultLimit = 100;
    filters.limit = filters.limit || defaultLimit;

    const query = {};

    if (filters.hostname) {
      query.hostname = filters.hostname;
    }

    if (filters.hostnames && filters.hostnames.length > 0) {
      query.hostname = { $in: filters.hostnames };
    }

    if (filters.pid) {
      query.pid = filters.pid;
    }

    if (filters.sources) {
      query.source = { $in: filters.sources };
    }

    if (filters.levels) {
      query.level = { $in: filters.levels };
    }

    if (filters.level_json) {
      query.$or = filters.level_json.map(levelObj => ({
        $and: [{ source: levelObj.source }, { level: levelObj.level }]
      }));
    }

    if (filters.level_json || filters.errsole_id) {
      const orConditions = [];
      if (filters.level_json && filters.level_json.length > 0) {
        const levelConditions = filters.level_json.map(levelObj => ({
          source: levelObj.source,
          level: levelObj.level
        }));

        orConditions.push(...levelConditions);
      }
      if (filters.errsole_id) {
        orConditions.push({ errsole_id: Number(filters.errsole_id) });
      }
      if (orConditions.length > 0) {
        query.$or = orConditions;
      }
    }

    let sortOrder = { _id: -1 };
    let shouldReverse = true;

    if (filters.lt_id) {
      query._id = { $lt: new ObjectId(filters.lt_id) };
      sortOrder = { _id: -1 };
      shouldReverse = true;
    } else if (filters.gt_id) {
      query._id = { $gt: new ObjectId(filters.gt_id) };
      sortOrder = { _id: 1 };
      shouldReverse = false;
    } else if (filters.lte_timestamp || filters.gte_timestamp) {
      query.timestamp = {};
      if (filters.lte_timestamp) {
        query.timestamp.$lte = filters.lte_timestamp;
        sortOrder = { timestamp: -1 };
        shouldReverse = true;
      }
      if (filters.gte_timestamp) {
        query.timestamp.$gte = filters.gte_timestamp;
        sortOrder = { timestamp: 1 };
        shouldReverse = false;
      }
    }

    const documents = await this.db.collection(this.logsCollectionName)
      .find(query, { projection: { meta: 0 } })
      .sort(sortOrder)
      .limit(filters.limit)
      .toArray();

    if (shouldReverse) {
      documents.reverse();
    }

    const formattedDocuments = documents.map(doc => {
      const { _id, ...rest } = doc;
      return { id: _id.toString(), ...rest };
    });

    return { items: formattedDocuments };
  }

  /**
   * Retrieves log entries from the database based on specified search terms and filters.
   *
   * @async
   * @function searchLogs
   * @param {string[]} searchTerms - An array of search terms.
   * @param {LogFilter} [filters] - Filters to refine the search.
   * @returns {Promise<{items: Log[]}>} - A promise that resolves with an object containing an array of log items.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async searchLogs (searchTerms, filters = {}) {
    const defaultLimit = 100;
    filters.limit = filters.limit || defaultLimit;

    const quotedTerms = searchTerms.map(term => `"${term}"`);
    const query = { $text: { $search: quotedTerms.join(' ') } };

    // Applying additional filters to the query
    if (filters.hostname) {
      query.hostname = filters.hostname;
    }

    if (filters.hostnames && filters.hostnames.length > 0) {
      query.hostname = { $in: filters.hostnames };
    }

    if (filters.pid) {
      query.pid = filters.pid;
    }

    if (filters.sources) {
      query.source = { $in: filters.sources };
    }

    if (filters.levels) {
      query.level = { $in: filters.levels };
    }

    if (filters.level_json) {
      query.$or = filters.level_json.map(levelObj => ({
        $and: [{ source: levelObj.source }, { level: levelObj.level }]
      }));
    }
    if (filters.level_json || filters.errsole_id) {
      const orConditions = [];
      if (filters.level_json && filters.level_json.length > 0) {
        const levelConditions = filters.level_json.map(levelObj => ({
          source: levelObj.source,
          level: levelObj.level
        }));

        orConditions.push(...levelConditions);
      }
      if (filters.errsole_id) {
        orConditions.push({ errsole_id: Number(filters.errsole_id) });
      }
      if (orConditions.length > 0) {
        query.$or = orConditions;
      }
    }

    let sortOrder = { timestamp: -1 };
    let shouldReverse = true;

    if (filters.lt_id) {
      query._id = { $lt: new ObjectId(filters.lt_id) };
      sortOrder = { _id: -1 };
      shouldReverse = true;
    } else if (filters.gt_id) {
      query._id = { $gt: new ObjectId(filters.gt_id) };
      sortOrder = { _id: 1 };
      shouldReverse = false;
    } else if (filters.lte_timestamp || filters.gte_timestamp) {
      query.timestamp = {};
      if (filters.lte_timestamp) {
        query.timestamp.$lte = filters.lte_timestamp;
        sortOrder = { timestamp: -1 };
        shouldReverse = true;
      }
      if (filters.gte_timestamp) {
        query.timestamp.$gte = filters.gte_timestamp;
        sortOrder = { timestamp: 1 };
        shouldReverse = false;
      }
    }

    const documents = await this.db.collection(this.logsCollectionName)
      .find(query, { projection: { meta: 0 } })
      .sort(sortOrder)
      .limit(filters.limit)
      .toArray();

    if (shouldReverse) {
      documents.reverse();
    }

    const formattedDocuments = documents.map(doc => {
      const { _id, ...rest } = doc;
      return { id: _id.toString(), ...rest };
    });

    return { items: formattedDocuments };
  }

  /**
   * Retrieves the meta data of a log entry.
   *
   * @async
   * @function getMeta
   * @param {string} id - The ID of the log entry.
   * @returns {Promise<{item: id, meta}>}- A promise that resolves with an object containing the meta data of the log entry.
   * @throws {Error} - Throws an error if the log entry is not found or the operation fails.
   */
  async getMeta (id) {
    const objectId = new ObjectId(id);
    const result = await this.db.collection(this.logsCollectionName).findOne({ _id: objectId }, { projection: { meta: 1 } });

    if (!result) {
      throw new Error('Log entry not found.');
    }

    return { item: { id: result._id, meta: result.meta } };
  }

  /**
   * Ensures that the Time To Live (TTL) configuration for logs is set.
   *
   * @async
   * @function ensureLogsTTL
   * @returns {Promise<{}>} - A promise that resolves with an empty object once the TTL configuration is confirmed or updated.
   */
  async ensureLogsTTL () {
    const DEFAULT_TTL = 2592000000; // 30 days in milliseconds
    try {
      let result = await this.getConfig('logsTTL');
      if (!result.item) {
        result = await this.setConfig('logsTTL', DEFAULT_TTL.toString());
      }
      await this.updateLogsCollectionTTL(result.item.value);
      await this.updateNotificationsCollectionTTL(result.item.value);
    } catch (err) {
      console.error(err);
    }
    return {};
  }

  /**
   * Updates the TTL index for the logs collection in the database.
   *
   * @async
   * @function updateLogsCollectionTTL
   * @param {number} logsTTL - The TTL value (in milliseconds) to set for logs expiration.
   * @returns {Promise<void>} - A promise that resolves with an empty object when the logs collection TTL is successfully updated.
   * @throws {Error} - Throws an error if updating the TTL index fails.
   */
  async updateLogsCollectionTTL (logsTTL) {
    const ttlInSeconds = parseInt(logsTTL) / 1000;
    const indexes = await this.db.collection(this.logsCollectionName).indexes();
    const ttlIndex = indexes.find(index => index.expireAfterSeconds && Object.keys(index.key).includes('timestamp'));
    if (!ttlIndex || ttlIndex.expireAfterSeconds !== ttlInSeconds) {
      if (ttlIndex) {
        await this.db.collection(this.logsCollectionName).dropIndex(ttlIndex.name);
      }
      await this.db.collection(this.logsCollectionName).createIndex({ timestamp: 1 }, { expireAfterSeconds: ttlInSeconds });
    }
    return {};
  }

  /**
   * Inserts a notification, counts today's notifications, and retrieves the previous notification.
   * @param {Notification} notification - The notification to be inserted.
   * @returns {Promise<Object>} - Returns today's notification count and the previous notification.
   */
  async insertNotificationItem (notification = {}) {
    const errsoleId = notification.errsole_id;
    const hostname = notification.hostname;
    const hashedMessage = notification.hashed_message;

    const session = this.db.client.startSession();

    try {
      const transactionOptions = {
        readPreference: 'primary',
        readConcern: { level: 'snapshot' },
        writeConcern: { w: 'majority' }
      };

      let result;
      await session.withTransaction(async () => {
        const notificationsCollection = this.db.collection(this.notificationsCollectionName);

        const previousNotificationItem = await notificationsCollection.findOne(
          { hostname, hashed_message: hashedMessage },
          { sort: { created_at: -1 }, session }
        );

        const timestamp = new Date();
        await notificationsCollection.insertOne(
          {
            errsole_id: errsoleId,
            hostname,
            hashed_message: hashedMessage,
            created_at: timestamp,
            updated_at: timestamp
          },
          { session }
        );

        const startOfDayUTC = new Date();
        startOfDayUTC.setUTCHours(0, 0, 0, 0);
        const endOfDayUTC = new Date();
        endOfDayUTC.setUTCHours(23, 59, 59, 999);
        const todayNotificationCount = await notificationsCollection.countDocuments(
          {
            hostname,
            hashed_message: hashedMessage,
            created_at: { $gte: startOfDayUTC, $lte: endOfDayUTC }
          },
          { session }
        );

        let formattedPreviousNotification;
        if (previousNotificationItem) {
          const { _id, ...rest } = previousNotificationItem;
          formattedPreviousNotification = { id: _id.toString(), ...rest };
        }

        result = {
          previousNotificationItem: formattedPreviousNotification,
          todayNotificationCount
        };
      }, transactionOptions);

      return result;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Updates the TTL index for the notifications collection in the database.
   *
   * @async
   * @function updateNotificationsCollectionTTL
   * @param {number} notificationsTTL - The TTL value (in milliseconds) to set for notifications expiration.
   * @returns {Promise<void>} - A promise that resolves with an empty object when the notifications collection TTL is successfully updated.
   * @throws {Error} - Throws an error if updating the TTL index fails.
   */
  async updateNotificationsCollectionTTL (notificationsTTL) {
    const ttlInSeconds = parseInt(notificationsTTL) / 1000;
    const indexes = await this.db.collection(this.notificationsCollectionName).indexes();
    const ttlIndex = indexes.find(index => index.expireAfterSeconds && Object.keys(index.key).includes('created_at'));
    if (!ttlIndex || ttlIndex.expireAfterSeconds !== ttlInSeconds) {
      if (ttlIndex) {
        await this.db.collection(this.notificationsCollectionName).dropIndex(ttlIndex.name);
      }
      await this.db.collection(this.notificationsCollectionName).createIndex({ created_at: 1 }, { expireAfterSeconds: ttlInSeconds });
    }
    return {};
  }

  /**
   * Creates a new user record in the database.
   *
   * @async
   * @function createUser
   * @param {Object} user - The user data.
   * @param {string} user.name - The name of the user.
   * @param {string} user.email - The email address of the user.
   * @param {string} user.password - The password of the user.
   * @param {string} user.role - The role of the user.
   * @returns {Promise<{item: User}>} - A promise that resolves with an object containing the new user item.
   * @throws {Error} - Throws an error if the user creation fails due to duplicate email or other database issues.
   */
  async createUser (user) {
    try {
      const hashedPassword = await bcrypt.hash(user.password, saltRounds);
      const userData = {
        ...user,
        hashed_password: hashedPassword
      };
      delete userData.password;

      const result = await this.db.collection(this.usersCollectionName).insertOne(userData);
      if (!result.insertedId) {
        throw new Error('Failed to insert the user record into the database.');
      }

      const newUser = await this.db.collection(this.usersCollectionName).findOne({ _id: result.insertedId }, { projection: { hashed_password: 0 } });
      const { _id, ...rest } = newUser;
      return { item: { id: _id.toString(), ...rest } };
    } catch (err) {
      if (err.code === 11000) {
        throw new Error('A user with the provided email already exists.');
      }
      throw err;
    }
  }

  /**
   * Verifies a user's credentials against stored records.
   *
   * @async
   * @function verifyUser
   * @param {string} email - The email address of the user.
   * @param {string} password - The password of the user
   * @returns {Promise<{item: User}>} - A promise that resolves with an object containing the user item upon successful verification.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async verifyUser (email, password) {
    if (!email || !password) {
      throw new Error('Email and password must be provided.');
    }

    const user = await this.db.collection(this.usersCollectionName).findOne({ email });
    if (!user) {
      throw new Error('User not found.');
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.hashed_password);
    if (!isPasswordCorrect) {
      throw new Error('Incorrect password.');
    }

    const returnUser = { ...user, id: user._id.toString() };
    delete returnUser._id;
    delete returnUser.hashed_password;

    return { item: returnUser };
  }

  /**
   * Retrieves the total count of users from the database.
   *
   * @async
   * @function getUserCount
   * @returns {Promise<{count: number}>} - A promise that resolves with an object containing the count of users.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getUserCount () {
    const count = await this.db.collection(this.usersCollectionName).countDocuments({});
    return { count };
  }

  /**
   * Retrieves all user records from the database.
   *
   * @async
   * @function getAllUsers
   * @returns {Promise<{items: User[]}>} - A promise that resolves with an object containing an array of user items.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getAllUsers () {
    const users = await this.db.collection(this.usersCollectionName).find({}, { projection: { hashed_password: 0 } }).toArray();
    const formattedUsers = users.map(user => {
      const { _id, ...rest } = user;
      return { id: _id.toString(), ...rest };
    });
    return { items: formattedUsers };
  }

  /**
   * Retrieves a user record from the database based on the provided email.
   *
   * @async
   * @function getUserByEmail
   * @param {string} email - The email address of the user.
   * @returns {Promise<{item: User}>} - A Promise that resolves with an object containing the user item.
   * @throws {Error} - Throws an error if no user matches the email address.
   */
  async getUserByEmail (email) {
    const user = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { hashed_password: 0 } });

    if (!user) {
      throw new Error('User not found.');
    }

    const { _id, ...userWithoutId } = user;
    return { item: { id: _id.toString(), ...userWithoutId } };
  }

  /**
   * Updates a user's record in the database based on the provided email.
   *
   * @async
   * @function updateUserByEmail
   * @param {string} email - The email address of the user to be updated.
   * @param {Object} updates - The updates to be applied to the user record.
   * @returns {Promise<{item: User}>} - A Promise that resolves with an object containing the updated user item.
   * @throws {Error} - Throws an error if no updates could be applied or the user is not found.
   */
  async updateUserByEmail (email, updates) {
    delete updates.hashed_password;
    const result = await this.db.collection(this.usersCollectionName).updateOne({ email }, { $set: updates });
    if (result.modifiedCount === 0) {
      throw new Error('No updates applied. User record not found or provided updates are identical to existing data.');
    }
    const updatedUser = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { hashed_password: 0 } });

    const { _id, ...userWithoutId } = updatedUser;
    return { item: { id: _id.toString(), ...userWithoutId } };
  }

  /**
   * Updates a user's password in the database.
   *
   * @async
   * @function updatePassword
   * @param {string} email - The email address of the user whose password is to be updated.
   * @param {string} currentPassword - The current password of the user for verification.
   * @param {string} newPassword - The new password to replace the current one.
   * @returns {Promise<{item: User}>} - A Promise that resolves with an object containing the updated user item (excluding sensitive information).
   * @throws {Error} - If the user is not found, if the current password is incorrect, or if the password update fails.
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
    const result = await this.db.collection(this.usersCollectionName).updateOne(
      { email },
      { $set: { hashed_password: hashedNewPassword } }
    );
    if (result.modifiedCount === 0) {
      throw new Error('Password update failed.');
    }
    const returnUser = { ...user, id: user._id.toString() };
    delete returnUser._id;
    delete returnUser.hashed_password;

    return { item: returnUser };
  }

  /**
   * Deletes a user record from the database.
   *
   * @async
   * @function deleteUser
   * @param {string} id - The unique ID of the user to be deleted.
   * @returns {Promise<{}>} - A Promise that resolves with an empty object upon successful deletion of the user.
   * @throws {Error} - Throws an error if no user is found with the given ID or if the database operation fails.
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
module.exports.default = ErrsoleMongoDB;

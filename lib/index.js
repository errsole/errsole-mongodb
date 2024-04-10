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

  /**
 * Ensures the necessary collections and their indexes are created in the database.
 * @async
 * @returns {Promise<void>} A promise that resolves when all collections and indexes are ensured.
 */
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
 * Posts one or more logs to the database.
 * @async
 * @param {Array<Objects>} logEntries
 * @returns {Promise<{}>}
 */
  async postLogs (logEntries) {
    while (this.isConnectionInProgress) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    await this.db.collection(this.logsCollectionName).insertMany(logEntries);
    return {};
  }

  /**
 * @async
 * @param {Object} filters - An object containing filtering options for retrieving logs. Options include start_datetime, level (e.g., 'info', 'error'), and limit (number).
 * @returns {Promise<Array<{id: string, message: string, level: string, timestamp: string}>>}
 **/
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

  /**
 * Searches for logs that match the given search term using full-text search.
 * @async
 * @param {string} searchTerm
 * @returns {Promise<Array<{id: string, message: string, level: string, timestamp: string}>>}
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
 * Creates a new user in the database.
 * @async
 * @param {Object} user
 * @returns {Promise<{status: boolean, message: string, error?: string}>}
 */
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
        return { status: true, message: 'created' };
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

  /**
 * Verifies a user's email and password.
 * @async
 * @param {{email: string, password: string}} userInfo
 * @returns {Promise<{name: string, email: string, role: string}>} returns without password
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
    return { ...user, password: undefined };
  }

  /**
 * Counts the number of users in the database.
 * @async
 * @returns {Promise<number>} The number of users.
 */
  async getNumberOfUsers () {
    const result = await this.db.collection(this.usersCollectionName).countDocuments({});
    return result;
  }

  /**
 * Retrieves all users from the database, excluding their passwords.
 * @async
 * @returns {Promise<{status: boolean, data: Array<Object>, error?: string}>}
 */
  async getAllUsers () {
    try {
      const users = await this.db.collection(this.usersCollectionName).find({}, { projection: { password: 0 } }).toArray();

      const transformedUsers = users.map(user => {
        const transformedUser = { ...user, id: user._id };
        delete transformedUser._id; // Remove the _id field
        return transformedUser;
      });

      return { status: true, data: transformedUsers };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  /**
 * Retrieves a configuration value by its name.
 * @async
 * @param {string} name
 * @returns {Promise<{value: string} | null>}
 */
  async getConfig (name) {
    try {
      const result = await this.db.collection(this.configCollectionName).findOne({ name });
      return result ? result.value : null;
    } catch (error) {
      console.error('Error retrieving configuration:', error);
      throw error;
    }
  }

  /**
 * Sets a configuration value, creating or updating as necessary.
 * @async
 * @param {string} name
 * @param {string} value
 * @returns {Promise<{status: boolean, message: string, error?: string}>}
 */
  async setConfig (name, value) {
    try {
      const result = await this.db.collection(this.configCollectionName).updateOne(
        { name },
        { $set: { value } },
        { upsert: true }
      );

      if (result.upsertedCount > 0) {
        return { status: true, message: 'created' };
      } else {
        return { status: false, error: 'No operation was performed' };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  /**
 * Retrieves a user's profile by email, excluding the password.
 * @async
 * @param {string} email
 * @returns {Promise<{status: boolean, data: Object, error?: string}>}
 */
  async getUserProfile (email) {
    if (!email) {
      return { status: false, error: 'Email is required' };
    }
    try {
      const user = await this.db.collection(this.usersCollectionName).findOne({ email }, { projection: { password: 0 } });
      if (user) {
        user.id = user._id;
        delete user._id;
        return { status: true, data: user };
      } else {
        return { status: false, error: 'User not found' };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  /**
 * Updates a user's profile information based on the provided updates object.
 * @async
 * @param {string} email
 * @param {Object} updates
 * @returns {Promise<{status: boolean, message: string, error?: string}>}
 */
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

  /**
 * Updates a user's password.
 * @async
 * @param {string} email
 * @param {string} currentPassword
 * @param {string} newPassword
 * @returns {Promise<{status: boolean, message: string, error?: string}>}
 */
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

  /**
 * @async
 * @param {string} userId
 * @returns {Promise<{status: boolean, message: string, error?: string}>}
 */
  async removeUser (userId) {
    if (!userId) {
      return { status: false, error: 'User ID is required' };
    }
    try {
      const id = new ObjectId(userId);
      const deleteResult = await this.db.collection(this.usersCollectionName).deleteOne({ _id: id });
      if (deleteResult.deletedCount === 0) {
        return { status: false, error: 'User not found' };
      }
      return { status: true, message: 'User removed successfully' };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }
}

module.exports = ErrsoleMongoDB;

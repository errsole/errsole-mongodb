const { MongoClient } = require('mongodb');
const ErrsoleMongoDB = require('./../lib/index');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');

/* globals expect, jest, beforeEach, it, afterEach, describe */

jest.mock('mongodb', () => ({
  MongoClient: jest.fn().mockReturnValue({
    connect: jest.fn(),
    db: jest.fn().mockReturnThis(),
    collection: jest.fn().mockReturnThis(),
    createIndex: jest.fn(),
    dropIndex: jest.fn(),
    find: jest.fn().mockReturnThis(),
    findOne: jest.fn(),
    insertMany: jest.fn(),
    insertOne: jest.fn(),
    deleteOne: jest.fn(),
    updateOne: jest.fn(),
    countDocuments: jest.fn(),
    indexes: jest.fn(),
    listCollections: jest.fn().mockReturnThis(),
    toArray: jest.fn()
  }),
  ObjectId: jest.fn().mockImplementation(id => ({ id }))
}));

const mockLogsCollection = {
  createIndex: jest.fn(),
  dropIndex: jest.fn(),
  insertMany: jest.fn(),
  findOne: jest.fn(),
  insertOne: jest.fn(),
  deleteOne: jest.fn(),
  updateOne: jest.fn(),
  countDocuments: jest.fn(),
  find: jest.fn().mockReturnThis(),
  toArray: jest.fn()
};

const mockDb = {
  collection: jest.fn().mockReturnValue(mockLogsCollection),
  listCollections: jest.fn().mockReturnValue({
    toArray: jest.fn().mockResolvedValue([
      { name: 'errsole_logs' },
      { name: 'errsole_users' },
      { name: 'errsole_config' }
    ])
  }),
  createCollection: jest.fn()
};

const mockClient = {
  connect: jest.fn(),
  db: jest.fn().mockReturnValue(mockDb)
};

MongoClient.mockReturnValue(mockClient);

describe('ErrsoleMongoDB', () => {
  let errsole;
  let originalConsoleError;
  let cronJob;

  beforeEach(() => {
    jest.clearAllMocks();
    errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');

    // Mock setInterval and cron.schedule
    jest.useFakeTimers();
    jest.spyOn(global, 'setInterval');
    cronJob = { stop: jest.fn() };
    jest.spyOn(cron, 'schedule').mockReturnValue(cronJob);

    // Suppress console.error
    originalConsoleError = console.error;
    console.error = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
    // Restore console.error
    console.error = originalConsoleError;
  });

  describe('init', () => {
    it('should initialize the connection and ensure collections', async () => {
      await errsole.init();
      expect(mockClient.connect).toHaveBeenCalled();
      expect(mockDb.listCollections).toHaveBeenCalled();
    });
  });

  describe('ensureCollections', () => {
    it('should ensure collections and indexes are created if they do not exist', async () => {
      mockDb.listCollections().toArray.mockResolvedValue([]);

      await errsole.ensureCollections();

      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_logs');
      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_users');
      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_config');

      expect(mockDb.collection('errsole_logs').createIndex).toHaveBeenCalledWith({ source: 1, level: 1, _id: 1 });
      expect(mockDb.collection('errsole_logs').createIndex).toHaveBeenCalledWith({ source: 1, level: 1, timestamp: 1 });
      expect(mockDb.collection('errsole_logs').createIndex).toHaveBeenCalledWith({ hostname: 1, pid: 1, _id: 1 });
      expect(mockDb.collection('errsole_logs').createIndex).toHaveBeenCalledWith({ message: 'text' });

      expect(mockDb.collection('errsole_users').createIndex).toHaveBeenCalledWith({ email: 1 }, { unique: true });

      expect(mockDb.collection('errsole_config').dropIndex).toHaveBeenCalledWith('name_1');
      expect(mockDb.collection('errsole_config').createIndex).toHaveBeenCalledWith({ key: 1 }, { unique: true });
    });
  });

  describe('getConfig', () => {
    it('should retrieve a config item', async () => {
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', key: 'logsTTL', value: '2592000000' });
      const result = await errsole.getConfig('logsTTL');
      expect(result.item.id).toBe('123');
      expect(result.item.key).toBe('logsTTL');
      expect(result.item.value).toBe('2592000000');
    });
  });

  describe('setConfig', () => {
    it('should update or insert a config item', async () => {
      mockLogsCollection.updateOne.mockResolvedValue({ matchedCount: 0, upsertedCount: 1 });
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', key: 'logsTTL', value: '2592000000' });
      const result = await errsole.setConfig('logsTTL', '2592000000');
      expect(result.item.id).toBe('123');
      expect(result.item.key).toBe('logsTTL');
      expect(result.item.value).toBe('2592000000');
    });
  });

  describe('deleteConfig', () => {
    it('should delete a config item', async () => {
      mockLogsCollection.deleteOne.mockResolvedValue({ deletedCount: 1 });
      const result = await errsole.deleteConfig('logsTTL');
      expect(result).toEqual({});
    });
  });

  describe('postLogs', () => {
    it('should add log entries to pending logs', () => {
      errsole.postLogs([{ message: 'log1' }, { message: 'log2' }]);
      expect(errsole.pendingLogs.length).toBe(2);
    });
  });

  describe('flushLogs', () => {
    it('should flush pending logs to the database', async () => {
      errsole.pendingLogs.push({ message: 'log1' });
      mockLogsCollection.insertMany.mockResolvedValue({});
      const result = await errsole.flushLogs();
      expect(result).toEqual({});
      expect(mockLogsCollection.insertMany).toHaveBeenCalledWith([{ message: 'log1' }]);
    });
  });

  describe('getLogs', () => {
    it('should retrieve log entries based on filters', async () => {
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.find.mockReturnValue({ sort: jest.fn().mockReturnThis(), limit: jest.fn().mockReturnThis(), toArray: jest.fn().mockResolvedValue(logs) });
      const result = await errsole.getLogs();
      expect(result.items[0].id).toBe('123');
      expect(result.items[0].message).toBe('log1');
    });
  });

  describe('searchLogs', () => {
    it('should search log entries based on search terms and filters', async () => {
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.find.mockReturnValue({ sort: jest.fn().mockReturnThis(), limit: jest.fn().mockReturnThis(), toArray: jest.fn().mockResolvedValue(logs) });
      const result = await errsole.searchLogs(['error']);
      expect(result.items[0].id).toBe('123');
      expect(result.items[0].message).toBe('log1');
    });
  });

  describe('ensureLogsTTL', () => {
    it('should ensure the TTL configuration for logs is set', async () => {
      errsole.getConfig = jest.fn().mockResolvedValue({});
      errsole.setConfig = jest.fn().mockResolvedValue({ item: { value: '2592000000' } });
      errsole.updateLogsCollectionTTL = jest.fn().mockResolvedValue({});
      await errsole.ensureLogsTTL();
      expect(errsole.updateLogsCollectionTTL).toHaveBeenCalledWith('2592000000');
    });
  });

  describe('createUser', () => {
    it('should create a new user', async () => {
      bcrypt.hash = jest.fn().mockResolvedValue('hashed_password');
      mockLogsCollection.insertOne.mockResolvedValue({ insertedId: '123' });
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', name: 'John', email: 'john@example.com' });
      const result = await errsole.createUser({ name: 'John', email: 'john@example.com', password: 'password', role: 'admin' });
      expect(result.item.id).toBe('123');
      expect(result.item.name).toBe('John');
      expect(result.item.email).toBe('john@example.com');
    });
  });

  describe('verifyUser', () => {
    it('should verify user credentials', async () => {
      bcrypt.compare = jest.fn().mockResolvedValue(true);
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', name: 'John', email: 'john@example.com', hashed_password: 'hashed_password' });
      const result = await errsole.verifyUser('john@example.com', 'password');
      expect(result.item.id).toBe('123');
      expect(result.item.name).toBe('John');
      expect(result.item.email).toBe('john@example.com');
    });
  });

  describe('getUserCount', () => {
    it('should retrieve the total count of users', async () => {
      mockLogsCollection.countDocuments.mockResolvedValue(5);
      const result = await errsole.getUserCount();
      expect(result.count).toBe(5);
    });
  });

  describe('getAllUsers', () => {
    it('should retrieve all user records', async () => {
      const users = [{ _id: '123', name: 'John', email: 'john@example.com' }];
      mockLogsCollection.find.mockReturnValue({ toArray: jest.fn().mockResolvedValue(users) });
      const result = await errsole.getAllUsers();
      expect(result.items[0].id).toBe('123');
      expect(result.items[0].name).toBe('John');
    });
  });

  describe('getUserByEmail', () => {
    it('should retrieve a user record by email', async () => {
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', name: 'John', email: 'john@example.com' });
      const result = await errsole.getUserByEmail('john@example.com');
      expect(result.item.id).toBe('123');
      expect(result.item.name).toBe('John');
    });
  });

  describe('updateUserByEmail', () => {
    it('should update a user record by email', async () => {
      mockLogsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', name: 'John', email: 'john@example.com' });
      const result = await errsole.updateUserByEmail('john@example.com', { name: 'John Doe' });
      expect(result.item.id).toBe('123');
      expect(result.item.name).toBe('John');
    });
  });

  describe('updatePassword', () => {
    it('should update a user\'s password', async () => {
      bcrypt.compare = jest.fn().mockResolvedValue(true);
      bcrypt.hash = jest.fn().mockResolvedValue('new_hashed_password');
      mockLogsCollection.findOne.mockResolvedValue({ _id: '123', name: 'John', email: 'john@example.com', hashed_password: 'hashed_password' });
      mockLogsCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      const result = await errsole.updatePassword('john@example.com', 'password', 'new_password');
      expect(result.item.id).toBe('123');
      expect(result.item.name).toBe('John');
    });
  });

  describe('deleteUser', () => {
    it('should delete a user record', async () => {
      mockLogsCollection.deleteOne.mockResolvedValue({ deletedCount: 1 });
      const result = await errsole.deleteUser('123');
      expect(result).toEqual({});
      expect(mockLogsCollection.deleteOne).toHaveBeenCalledWith({ _id: { id: '123' } });
    });
  });
});

const { MongoClient, ObjectId } = require('mongodb');
const ErrsoleMongoDB = require('./../lib/index');
const cron = require('node-cron');
const bcrypt = require('bcryptjs');

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

jest.mock('bcryptjs', () => ({
  hash: jest.fn(),
  compare: jest.fn()
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
  deleteMany: jest.fn(),
  drop: jest.fn(),
  indexes: jest.fn().mockResolvedValue([
    { key: { timestamp: 1 }, expireAfterSeconds: 2592000, name: 'timestamp_1' }
  ]),
  find: jest.fn().mockReturnThis(),
  sort: jest.fn().mockReturnThis(),
  limit: jest.fn().mockReturnThis(),
  toArray: jest.fn(),
  distinct: jest.fn()
};

const mockUsersCollection = {
  createIndex: jest.fn(),
  insertOne: jest.fn(),
  findOne: jest.fn(),
  find: jest.fn().mockReturnThis(),
  countDocuments: jest.fn(),
  updateOne: jest.fn(),
  deleteOne: jest.fn(),
  toArray: jest.fn()
};

const mockNotificationsCollection = {
  createIndex: jest.fn(),
  deleteMany: jest.fn()
  // Add other methods if your class interacts with them
};

const mockDb = {
  collection: jest.fn().mockImplementation(name => {
    if (name === 'errsole_logs') return mockLogsCollection;
    if (name === 'errsole_users') return mockUsersCollection;
    if (name === 'errsole_notifications') return mockNotificationsCollection;
    // Add other collections as needed
    return mockLogsCollection;
  }),
  listCollections: jest.fn().mockReturnValue({
    toArray: jest.fn().mockResolvedValue([
      { name: 'errsole_logs' },
      { name: 'errsole_users' },
      { name: 'errsole_config' },
      { name: 'errsole_notifications' }
    ])
  }),
  createCollection: jest.fn(),
  client: null
};

const mockClient = {
  connect: jest.fn(),
  db: jest.fn().mockReturnValue(mockDb),
  startSession: jest.fn().mockReturnValue({
    withTransaction: jest.fn().mockImplementation(async (callback) => {
      await callback();
    }),
    endSession: jest.fn()
  })
};

mockDb.client = mockClient;

MongoClient.mockReturnValue(mockClient);

describe('ErrsoleMongoDB', () => {
  let errsole;
  let originalConsoleError;
  let cronJob;

  beforeEach(() => {
    jest.clearAllMocks();
    errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');

    jest.useFakeTimers();
    jest.spyOn(global, 'setInterval');
    cronJob = { stop: jest.fn() };
    jest.spyOn(cron, 'schedule').mockReturnValue(cronJob);

    originalConsoleError = console.error;
    console.error = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
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

      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_users');
      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_config');
      expect(mockDb.createCollection).toHaveBeenCalledWith('errsole_notifications');

      expect(mockDb.collection('errsole_logs_v2').createIndex).toHaveBeenCalledWith(
        expect.objectContaining({ source: 1, level: 1 })
      );
      expect(mockDb.collection('errsole_logs_v2').createIndex).toHaveBeenCalledWith(
        expect.objectContaining({ hostname: 1, timestamp: 1 })
      );
      expect(mockDb.collection('errsole_logs_v2').createIndex).toHaveBeenCalledWith(
        expect.objectContaining({ errsole_id: 1 })
      );

      expect(mockDb.collection('errsole_users').createIndex).toHaveBeenCalledWith({ email: 1 }, { unique: true });
      expect(mockDb.collection('errsole_config').createIndex).toHaveBeenCalledWith({ key: 1 }, { unique: true });
      expect(mockDb.collection('errsole_notifications').createIndex).toHaveBeenCalledWith(
        expect.objectContaining({ hostname: 1, hashed_message: 1, created_at: 1 })
      );
    });
  });

  describe('getConfig', () => {
    it('should retrieve the configuration item successfully', async () => {
      const key = 'testKey';
      const mockResult = { _id: 'mockId', key, value: 'testValue' };

      mockLogsCollection.findOne.mockResolvedValue(mockResult);

      const result = await errsole.getConfig(key);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith({ key });
      expect(result).toEqual({ item: { id: 'mockId', key, value: 'testValue' } });
    });

    it('should return an empty object if the configuration item is not found', async () => {
      const key = 'nonExistentKey';

      mockLogsCollection.findOne.mockResolvedValue(null);

      const result = await errsole.getConfig(key);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith({ key });
      expect(result).toEqual({});
    });

    it('should propagate database error during retrieval', async () => {
      const key = 'errorKey';
      const mockError = new Error('Database retrieval error');

      mockLogsCollection.findOne.mockRejectedValue(mockError);

      await expect(errsole.getConfig(key)).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith({ key });
    });
  });

  describe('setConfig', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should update the configuration successfully', async () => {
      const key = 'testKey';
      const value = 'testValue';
      const mockResult = { matchedCount: 1, upsertedCount: 0 };
      const mockSavedItem = { _id: 'mockId', key, value };

      mockLogsCollection.updateOne.mockResolvedValue(mockResult);
      mockLogsCollection.findOne.mockResolvedValue(mockSavedItem);

      const result = await errsole.setConfig(key, value);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.updateOne).toHaveBeenCalledWith(
        { key },
        { $set: { value } },
        { upsert: true }
      );
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith({ key });
      expect(result).toEqual({ item: { id: 'mockId', key, value } });
    });

    it('should insert the configuration successfully', async () => {
      const key = 'newKey';
      const value = 'newValue';
      const mockResult = { matchedCount: 0, upsertedCount: 1 };
      const mockSavedItem = { _id: 'mockId', key, value };

      mockLogsCollection.updateOne.mockResolvedValue(mockResult);
      mockLogsCollection.findOne.mockResolvedValue(mockSavedItem);

      const result = await errsole.setConfig(key, value);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.updateOne).toHaveBeenCalledWith(
        { key },
        { $set: { value } },
        { upsert: true }
      );
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith({ key });
      expect(result).toEqual({ item: { id: 'mockId', key, value } });
    });

    it('should throw an error if update or insert fails', async () => {
      const key = 'failKey';
      const value = 'failValue';
      const mockResult = { matchedCount: 0, upsertedCount: 0 };

      mockLogsCollection.updateOne.mockResolvedValue(mockResult);

      await expect(errsole.setConfig(key, value)).rejects.toThrow('Failed to update or insert configuration.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.updateOne).toHaveBeenCalledWith(
        { key },
        { $set: { value } },
        { upsert: true }
      );
    });

    it('should propagate database error during update or insert', async () => {
      const key = 'errorKey';
      const value = 'errorValue';
      const mockError = new Error('Database error');

      mockLogsCollection.updateOne.mockRejectedValue(mockError);

      await expect(errsole.setConfig(key, value)).rejects.toThrow('Database error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.updateOne).toHaveBeenCalledWith(
        { key },
        { $set: { value } },
        { upsert: true }
      );
    });

    it('should propagate database error during retrieval', async () => {
      const key = 'retrieveKey';
      const value = 'retrieveValue';
      const mockResult = { matchedCount: 1, upsertedCount: 0 };
      const mockError = new Error('Database retrieval error');

      mockLogsCollection.updateOne.mockResolvedValue(mockResult);
      mockLogsCollection.findOne.mockRejectedValue(mockError);

      await expect(errsole.setConfig(key, value)).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.updateOne).toHaveBeenCalledWith(
        { key },
        { $set: { value } },
        { upsert: true }
      );
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith({ key });
    });
  });

  describe('deleteConfig', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should delete the configuration item successfully', async () => {
      const key = 'testKey';
      const mockResult = { deletedCount: 1 };

      mockLogsCollection.deleteOne.mockResolvedValue(mockResult);

      const result = await errsole.deleteConfig(key);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.deleteOne).toHaveBeenCalledWith({ key });
      expect(result).toEqual({});
    });

    it('should throw an error if deletion fails', async () => {
      const key = 'nonExistentKey';
      const mockResult = { deletedCount: 0 };

      mockLogsCollection.deleteOne.mockResolvedValue(mockResult);

      await expect(errsole.deleteConfig(key)).rejects.toThrow('Failed to delete configuration.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.deleteOne).toHaveBeenCalledWith({ key });
    });

    it('should propagate database error during deletion', async () => {
      const key = 'errorKey';
      const mockError = new Error('Database deletion error');

      mockLogsCollection.deleteOne.mockRejectedValue(mockError);

      await expect(errsole.deleteConfig(key)).rejects.toThrow('Database deletion error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_config');
      expect(mockLogsCollection.deleteOne).toHaveBeenCalledWith({ key });
    });
  });

  describe('postLogs', () => {
    it('should add log entries to pendingLogs', () => {
      const logEntries = [{ message: 'log1' }, { message: 'log2' }];
      errsole.postLogs(logEntries);
      expect(errsole.pendingLogs).toEqual(logEntries);
    });

    it('should call flushLogs if pendingLogs length reaches batchSize', () => {
      errsole.batchSize = 2;
      const logEntries = [{ message: 'log1' }, { message: 'log2' }];
      const flushLogsSpy = jest.spyOn(errsole, 'flushLogs').mockImplementation(() => {});

      errsole.postLogs(logEntries);

      expect(flushLogsSpy).toHaveBeenCalled();
      flushLogsSpy.mockRestore();
    });

    it('should not call flushLogs if pendingLogs length is less than batchSize', () => {
      errsole.batchSize = 3;
      const logEntries = [{ message: 'log1' }, { message: 'log2' }];
      const flushLogsSpy = jest.spyOn(errsole, 'flushLogs').mockImplementation(() => {});

      errsole.postLogs(logEntries);

      expect(flushLogsSpy).not.toHaveBeenCalled();
      flushLogsSpy.mockRestore();
    });
  });

  describe('flushLogs', () => {
    it('should return immediately if there are no logs to flush', async () => {
      errsole.pendingLogs = [];
      const result = await errsole.flushLogs();
      expect(result).toEqual({});
      expect(mockDb.collection('errsole_logs').insertMany).not.toHaveBeenCalled();
    });

    it('should wait until connection is ready before flushing logs', async () => {
      errsole.isConnectionInProgress = true;
      errsole.pendingLogs = [{ message: 'log1' }];

      setTimeout(() => {
        errsole.isConnectionInProgress = false;
      }, 200);

      const flushLogsPromise = errsole.flushLogs();
      jest.advanceTimersByTime(200);

      const result = await flushLogsPromise;
      expect(result).toEqual({});
      expect(mockDb.collection('errsole_logs').insertMany).toHaveBeenCalledWith([{ message: 'log1' }]);
    });

    it('should flush logs to the database when there are logs to flush', async () => {
      errsole.isConnectionInProgress = false;
      errsole.pendingLogs = [{ message: 'log1' }, { message: 'log2' }];

      const result = await errsole.flushLogs();
      expect(result).toEqual({});
      expect(mockDb.collection('errsole_logs').insertMany).toHaveBeenCalledWith([{ message: 'log1' }, { message: 'log2' }]);
    });

    it('should handle errors during log flushing gracefully', async () => {
      errsole.isConnectionInProgress = false;
      errsole.pendingLogs = [{ message: 'log1' }];
      const error = new Error('Insertion failed');
      mockDb.collection('errsole_logs').insertMany.mockRejectedValue(error);

      const result = await errsole.flushLogs();
      expect(result).toBe(error);
    });
  });

  describe('getLogs', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should retrieve logs with default limit', async () => {
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs();
      expect(result.items.length).toBe(1);
      expect(mockLogsCollection.find).toHaveBeenCalledWith({}, { projection: { meta: 0 } });
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ _id: -1 });
      expect(mockLogsCollection.limit).toHaveBeenCalledWith(100);
    });

    it('should set lt_id filter correctly', async () => {
      const filters = { lt_id: '60a6cbbd8574f2a0d24c4d5e' };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs(filters);
      expect(result.items.length).toBe(1);
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        _id: { $lt: new ObjectId('60a6cbbd8574f2a0d24c4d5e') }
      }, { projection: { meta: 0 } });
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ _id: -1 });
    });

    it('should set gt_id filter correctly', async () => {
      const filters = { gt_id: '60a6cbbd8574f2a0d24c4d5e' };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs(filters);
      expect(result.items.length).toBe(1);
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        _id: { $gt: new ObjectId('60a6cbbd8574f2a0d24c4d5e') }
      }, { projection: { meta: 0 } });
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ _id: 1 });
    });

    it('should apply both lte_timestamp and gte_timestamp filters with final sort order from gte_timestamp and not reverse documents', async () => {
      const filters = { lte_timestamp: 1630000000000, gte_timestamp: 1620000000000 };
      const logs = [
        { _id: '1', message: 'log1' },
        { _id: '2', message: 'log2' },
        { _id: '3', message: 'log3' }
      ];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs(filters);

      // Verify that find is called with both timestamp conditions
      expect(mockLogsCollection.find).toHaveBeenCalledWith(
        { timestamp: { $lte: 1630000000000, $gte: 1620000000000 } },
        { projection: { meta: 0 } }
      );
      // The final sort order comes from the gte_timestamp block
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ timestamp: 1, _id: 1 });
      // Since shouldReverse is false, the first item remains unchanged
      expect(result.items[0].id).toBe(logs[0]._id);
    });

    it('should set level_json filter correctly', async () => {
      const filters = {
        level_json: [
          { source: 'source1', level: 'info' },
          { source: 'source2', level: 'error' }
        ]
      };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs(filters);
      expect(result.items.length).toBe(1);
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        $or: [
          { source: 'source1', level: 'info' },
          { source: 'source2', level: 'error' }
        ]
      }, { projection: { meta: 0 } });
    });

    it('should reverse documents if shouldReverse is true', async () => {
      const filters = { lt_id: '60a6cbbd8574f2a0d24c4d5e' };
      const logs = [{ _id: '123', message: 'log1' }, { _id: '124', message: 'log2' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs(filters);
      expect(result.items[0].id).toBe('124');
    });

    it('should not reverse documents if shouldReverse is false', async () => {
      const filters = { gt_id: '60a6cbbd8574f2a0d24c4d5e' };
      const logs = [{ _id: '123', message: 'log1' }, { _id: '124', message: 'log2' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs(filters);
      expect(result.items[0].id).toBe('123');
    });

    it('should format the returned documents correctly', async () => {
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.getLogs();
      expect(result.items[0]).toEqual({ id: '123', message: 'log1' });
    });

    it('should apply hostnames filter using $in operator when filters.hostnames is provided', async () => {
      const filters = { hostnames: ['host1', 'host2'] };
      const mockLogs = [{ _id: '123', message: 'log1' }, { _id: '124', message: 'log2' }];

      mockLogsCollection.toArray.mockResolvedValue(mockLogs);

      const result = await errsole.getLogs(filters);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        hostname: { $in: ['host1', 'host2'] }
      }, { projection: { meta: 0 } });
      expect(result.items.length).toBe(2);
    });

    it('should apply errsole_id filter and push to $or condition when filters.errsole_id is provided', async () => {
      const filters = { errsole_id: 101 };
      const mockLogs = [{ _id: '123', message: 'log1' }];

      mockLogsCollection.toArray.mockResolvedValue(mockLogs);

      const result = await errsole.getLogs(filters);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        $or: [{ errsole_id: 101 }]
      }, { projection: { meta: 0 } });
      expect(result.items.length).toBe(1);
    });
  });

  describe('searchLogs', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should search logs with default limit', async () => {
      const searchTerms = ['error'];
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms);
      expect(result.items.length).toBe(1);
      expect(mockLogsCollection.find).toHaveBeenCalledWith(
        { $text: { $search: '"error"' } },
        { projection: { meta: 0 } }
      );
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ _id: -1 });
      expect(mockLogsCollection.limit).toHaveBeenCalledWith(100);
    });

    it('should apply lte_timestamp filter correctly when only lte_timestamp is provided', async () => {
      const searchTerms = ['error'];
      // Provide lte_timestamp as a date string
      const givenTimestamp = '2021-05-03T00:00:00.000Z';
      const filters = { lte_timestamp: givenTimestamp };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms, filters);
      expect(result).toBeDefined();

      // Convert the provided timestamp into a Date and compute expected $gte as (givenTimestamp - 24 hours)
      const lteDate = new Date(givenTimestamp);
      const expectedLte = lteDate.toISOString();
      const gteDate = new Date(lteDate.getTime() - 24 * 60 * 60 * 1000);
      const expectedGte = gteDate.toISOString();

      // Verify that find is called with a query that includes the timestamp filter
      expect(mockLogsCollection.find).toHaveBeenCalledWith(
        {
          $text: { $search: '"error"' },
          timestamp: { $lte: expectedLte, $gte: expectedGte }
        },
        { projection: { meta: 0 } }
      );
      // Verify sort order is set from the lte block
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ timestamp: -1, _id: -1 });
    });

    it('should apply gte_timestamp filter correctly when only gte_timestamp is provided', async () => {
      const searchTerms = ['error'];
      const givenTimestamp = '2021-05-04T00:00:00.000Z';
      const filters = { gte_timestamp: givenTimestamp };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms, filters);
      expect(result).toBeDefined();

      // Convert the provided timestamp into a Date and compute expected $lte as (givenTimestamp + 24 hours)
      const gteDate = new Date(givenTimestamp);
      const expectedGte = gteDate.toISOString();
      const lteDate = new Date(gteDate.getTime() + 24 * 60 * 60 * 1000);
      const expectedLte = lteDate.toISOString();

      // Verify that find is called with the correct timestamp filter
      expect(mockLogsCollection.find).toHaveBeenCalledWith(
        {
          $text: { $search: '"error"' },
          timestamp: { $gte: expectedGte, $lte: expectedLte }
        },
        { projection: { meta: 0 } }
      );
      // Verify sort order is set from the gte block
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ timestamp: 1, _id: 1 });
    });

    it('should apply both lte_timestamp and gte_timestamp filters correctly when both are provided', async () => {
      const searchTerms = ['error'];
      const givenLteTimestamp = '2021-05-04T00:00:00.000Z';
      const givenGteTimestamp = '2021-05-03T00:00:00.000Z';
      const filters = { lte_timestamp: givenLteTimestamp, gte_timestamp: givenGteTimestamp };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms, filters);
      expect(result).toBeDefined();

      const lteDate = new Date(givenLteTimestamp);
      const gteDate = new Date(givenGteTimestamp);
      const expectedLte = lteDate.toISOString();
      const expectedGte = gteDate.toISOString();

      // When both filters are provided, no additional boundaries are computed.
      expect(mockLogsCollection.find).toHaveBeenCalledWith(
        {
          $text: { $search: '"error"' },
          timestamp: { $lte: expectedLte, $gte: expectedGte }
        },
        { projection: { meta: 0 } }
      );
      // Final sort order is determined by the gte_timestamp block.
      expect(mockLogsCollection.sort).toHaveBeenCalledWith({ timestamp: 1, _id: 1 });
    });

    it('should set level_json filter correctly', async () => {
      const searchTerms = ['error'];
      const filters = {
        level_json: [
          { source: 'source1', level: 'info' },
          { source: 'source2', level: 'error' }
        ]
      };
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms, filters);
      expect(result.items.length).toBe(1);
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        $text: { $search: '"error"' },
        $or: [
          { source: 'source1', level: 'info' },
          { source: 'source2', level: 'error' }
        ]
      }, { projection: { meta: 0 } });
    });

    it('should reverse documents if shouldReverse is true', async () => {
      const searchTerms = ['error'];
      const filters = { lt_id: '60a6cbbd8574f2a0d24c4d5e' };
      const logs = [{ _id: '123', message: 'log1' }, { _id: '124', message: 'log2' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms, filters);
      expect(result.items[0].id).toBe('124');
    });

    it('should not reverse documents if shouldReverse is false', async () => {
      const searchTerms = ['error'];
      const filters = { gt_id: '60a6cbbd8574f2a0d24c4d5e' };
      const logs = [{ _id: '123', message: 'log1' }, { _id: '124', message: 'log2' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms, filters);
      expect(result.items[0].id).toBe('123');
    });

    it('should format the returned documents correctly', async () => {
      const searchTerms = ['error'];
      const logs = [{ _id: '123', message: 'log1' }];
      mockLogsCollection.toArray.mockResolvedValue(logs);

      const result = await errsole.searchLogs(searchTerms);
      expect(result.items[0]).toEqual({ id: '123', message: 'log1' });
    });

    it('should apply hostnames filter using $in operator when filters.hostnames is provided', async () => {
      const searchTerms = ['error'];
      const filters = { hostnames: ['host1', 'host2'] };
      const mockLogs = [{ _id: '123', message: 'log1' }, { _id: '124', message: 'log2' }];

      mockLogsCollection.toArray.mockResolvedValue(mockLogs);

      const result = await errsole.searchLogs(searchTerms, filters);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        $text: { $search: '"error"' },
        hostname: { $in: ['host1', 'host2'] }
      }, { projection: { meta: 0 } });
      expect(result.items.length).toBe(2);
    });

    it('should apply errsole_id filter and push to $or condition when filters.errsole_id is provided', async () => {
      const searchTerms = ['error'];
      const filters = { errsole_id: 101 };
      const mockLogs = [{ _id: '123', message: 'log1' }];

      mockLogsCollection.toArray.mockResolvedValue(mockLogs);

      const result = await errsole.searchLogs(searchTerms, filters);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.find).toHaveBeenCalledWith({
        $text: { $search: '"error"' },
        $or: [{ errsole_id: 101 }]
      }, { projection: { meta: 0 } });
      expect(result.items.length).toBe(1);
    });
  });

  describe('getMeta', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should retrieve the meta information successfully', async () => {
      const id = '60a6cbbd8574f2a0d24c4d5e';
      const objectId = new ObjectId(id);
      const mockResult = { _id: objectId, meta: { someMeta: 'data' } };

      mockLogsCollection.findOne.mockResolvedValue(mockResult);

      const result = await errsole.getMeta(id);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith(
        { _id: objectId },
        { projection: { meta: 1 } }
      );
      expect(result).toEqual({ item: { id: objectId, meta: { someMeta: 'data' } } });
    });

    it('should throw an error if the log entry is not found', async () => {
      const id = 'nonExistentId';
      const objectId = new ObjectId(id);

      mockLogsCollection.findOne.mockResolvedValue(null);

      await expect(errsole.getMeta(id)).rejects.toThrow('Log entry not found.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith(
        { _id: objectId },
        { projection: { meta: 1 } }
      );
    });

    it('should propagate database error during retrieval', async () => {
      const id = 'errorId';
      const objectId = new ObjectId(id);
      const mockError = new Error('Database retrieval error');

      mockLogsCollection.findOne.mockRejectedValue(mockError);

      await expect(errsole.getMeta(id)).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith(
        { _id: objectId },
        { projection: { meta: 1 } }
      );
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
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should create a new user successfully', async () => {
      const user = { name: 'John', email: 'john@example.com', password: 'password', role: 'admin' };
      const hashedPassword = 'hashed_password';
      const insertedId = new ObjectId();
      const newUser = { _id: insertedId, name: 'John', email: 'john@example.com', role: 'admin' };

      bcrypt.hash.mockResolvedValue(hashedPassword);
      mockUsersCollection.insertOne.mockResolvedValue({ insertedId });
      mockUsersCollection.findOne.mockResolvedValue(newUser);

      const result = await errsole.createUser(user);

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, expect.any(Number));
      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.insertOne).toHaveBeenCalledWith({
        name: 'John',
        email: 'john@example.com',
        role: 'admin',
        hashed_password: hashedPassword
      });
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ _id: insertedId }, { projection: { hashed_password: 0 } });
      expect(result).toEqual({ item: { id: insertedId.toString(), name: 'John', email: 'john@example.com', role: 'admin' } });
    });

    it('should throw an error if user insertion fails', async () => {
      const user = { name: 'John', email: 'john@example.com', password: 'password', role: 'admin' };
      const hashedPassword = 'hashed_password';

      bcrypt.hash.mockResolvedValue(hashedPassword);
      mockUsersCollection.insertOne.mockResolvedValue({ insertedId: null });

      await expect(errsole.createUser(user)).rejects.toThrow('Failed to insert the user record into the database.');

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, expect.any(Number));
      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.insertOne).toHaveBeenCalledWith({
        name: 'John',
        email: 'john@example.com',
        role: 'admin',
        hashed_password: hashedPassword
      });
    });

    it('should throw an error if email already exists', async () => {
      const user = { name: 'John', email: 'john@example.com', password: 'password', role: 'admin' };
      const hashedPassword = 'hashed_password';
      const duplicateKeyError = new Error('Duplicate key error');
      duplicateKeyError.code = 11000;

      bcrypt.hash.mockResolvedValue(hashedPassword);
      mockUsersCollection.insertOne.mockRejectedValue(duplicateKeyError);

      await expect(errsole.createUser(user)).rejects.toThrow('A user with the provided email already exists.');

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, expect.any(Number));
      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.insertOne).toHaveBeenCalledWith({
        name: 'John',
        email: 'john@example.com',
        role: 'admin',
        hashed_password: hashedPassword
      });
    });

    it('should propagate other database errors', async () => {
      const user = { name: 'John', email: 'john@example.com', password: 'password', role: 'admin' };
      const hashedPassword = 'hashed_password';
      const dbError = new Error('Database error');

      bcrypt.hash.mockResolvedValue(hashedPassword);
      mockUsersCollection.insertOne.mockRejectedValue(dbError);

      await expect(errsole.createUser(user)).rejects.toThrow('Database error');

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, expect.any(Number));
      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.insertOne).toHaveBeenCalledWith({
        name: 'John',
        email: 'john@example.com',
        role: 'admin',
        hashed_password: hashedPassword
      });
    });
  });

  describe('verifyUser', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should throw an error if email is not provided', async () => {
      await expect(errsole.verifyUser('', 'password')).rejects.toThrow('Email and password must be provided.');
    });

    it('should throw an error if password is not provided', async () => {
      await expect(errsole.verifyUser('john@example.com', '')).rejects.toThrow('Email and password must be provided.');
    });

    it('should throw an error if user is not found', async () => {
      const email = 'nonexistent@example.com';
      mockUsersCollection.findOne.mockResolvedValue(null);

      await expect(errsole.verifyUser(email, 'password')).rejects.toThrow('User not found.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
    });

    it('should throw an error if password is incorrect', async () => {
      const email = 'john@example.com';
      const password = 'wrongpassword';
      const user = {
        _id: new ObjectId(),
        email,
        hashed_password: 'hashed_password'
      };

      mockUsersCollection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(false);

      await expect(errsole.verifyUser(email, password)).rejects.toThrow('Incorrect password.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, user.hashed_password);
    });

    it('should verify the user successfully if email and password are correct', async () => {
      const email = 'john@example.com';
      const password = 'password';
      const user = {
        _id: new ObjectId(),
        email,
        name: 'John',
        hashed_password: 'hashed_password',
        role: 'admin'
      };

      mockUsersCollection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);

      const result = await errsole.verifyUser(email, password);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, user.hashed_password);

      const expectedUser = {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        role: user.role
      };

      expect(result).toEqual({ item: expectedUser });
    });

    it('should propagate database error during retrieval', async () => {
      const email = 'error@example.com';
      const password = 'password';
      const mockError = new Error('Database retrieval error');

      mockUsersCollection.findOne.mockRejectedValue(mockError);

      await expect(errsole.verifyUser(email, password)).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
    });

    it('should propagate bcrypt error during password comparison', async () => {
      const email = 'john@example.com';
      const password = 'password';
      const user = {
        _id: new ObjectId(),
        email,
        hashed_password: 'hashed_password'
      };
      const mockError = new Error('Bcrypt comparison error');

      mockUsersCollection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockRejectedValue(mockError);

      await expect(errsole.verifyUser(email, password)).rejects.toThrow('Bcrypt comparison error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, user.hashed_password);
    });
  });

  describe('getUserCount', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should retrieve the total count of users', async () => {
      const userCount = 5;
      mockUsersCollection.countDocuments.mockResolvedValue(userCount);

      const result = await errsole.getUserCount();

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.countDocuments).toHaveBeenCalledWith({});
      expect(result.count).toBe(userCount);
    });

    it('should handle errors during user count retrieval', async () => {
      const mockError = new Error('Database retrieval error');
      mockUsersCollection.countDocuments.mockRejectedValue(mockError);

      await expect(errsole.getUserCount()).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.countDocuments).toHaveBeenCalledWith({});
    });
  });

  describe('getAllUsers', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should retrieve all user records without hashed_password', async () => {
      const users = [
        { _id: new ObjectId(), name: 'John', email: 'john@example.com', role: 'admin', hashed_password: 'hashed_password' },
        { _id: new ObjectId(), name: 'Jane', email: 'jane@example.com', role: 'user', hashed_password: 'hashed_password' }
      ];

      const formattedUsers = users.map(user => ({
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role
      }));

      mockUsersCollection.find.mockReturnValue({
        toArray: jest.fn().mockResolvedValue(users.map(user => {
          const { hashed_password, ...rest } = user;
          return rest;
        }))
      });

      const result = await errsole.getAllUsers();

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.find).toHaveBeenCalledWith({}, { projection: { hashed_password: 0 } });
      expect(result.items.length).toBe(2);
      expect(result.items).toEqual(formattedUsers);
    });

    it('should return an empty array if no users are found', async () => {
      mockUsersCollection.find.mockReturnValue({ toArray: jest.fn().mockResolvedValue([]) });

      const result = await errsole.getAllUsers();

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.find).toHaveBeenCalledWith({}, { projection: { hashed_password: 0 } });
      expect(result.items).toEqual([]);
    });

    it('should handle errors during user retrieval', async () => {
      const mockError = new Error('Database retrieval error');
      mockUsersCollection.find.mockReturnValue({ toArray: jest.fn().mockRejectedValue(mockError) });

      await expect(errsole.getAllUsers()).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.find).toHaveBeenCalledWith({}, { projection: { hashed_password: 0 } });
    });
  });

  describe('getUserByEmail', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should retrieve a user record by email without hashed_password', async () => {
      const email = 'john@example.com';
      const user = {
        _id: new ObjectId(),
        name: 'John',
        email: 'john@example.com',
        role: 'admin',
        hashed_password: 'hashed_password'
      };

      const userWithoutPassword = {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      mockUsersCollection.findOne.mockResolvedValue(userWithoutPassword);

      const result = await errsole.getUserByEmail(email);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
      expect(result).toEqual({ item: { id: user._id.toString(), name: user.name, email: user.email, role: user.role } });
    });

    it('should throw an error if the user is not found', async () => {
      const email = 'nonexistent@example.com';

      mockUsersCollection.findOne.mockResolvedValue(null);

      await expect(errsole.getUserByEmail(email)).rejects.toThrow('User not found.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
    });

    it('should handle database retrieval errors', async () => {
      const email = 'error@example.com';
      const mockError = new Error('Database retrieval error');

      mockUsersCollection.findOne.mockRejectedValue(mockError);

      await expect(errsole.getUserByEmail(email)).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
    });
  });

  describe('updateUserByEmail', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');

      mockDb.collection.mockImplementation((name) => {
        if (name === 'errsole_users') {
          return mockUsersCollection;
        }
        return mockLogsCollection;
      });
    });

    it('should update a user record by email successfully', async () => {
      const email = 'john@example.com';
      const updates = { name: 'John Doe' };
      const updatedUser = {
        _id: new ObjectId(),
        name: 'John Doe',
        email: 'john@example.com',
        role: 'admin'
      };

      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockUsersCollection.findOne.mockResolvedValue(updatedUser);

      const result = await errsole.updateUserByEmail(email, updates);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: updates });
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
      expect(result).toEqual({ item: { id: updatedUser._id.toString(), name: 'John Doe', email: 'john@example.com', role: 'admin' } });
    });

    it('should throw an error if no updates are applied', async () => {
      const email = 'john@example.com';
      const updates = { name: 'John Doe' };

      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 0 });

      await expect(errsole.updateUserByEmail(email, updates)).rejects.toThrow('No updates applied. User record not found or provided updates are identical to existing data.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: updates });
    });

    it('should handle database update errors', async () => {
      const email = 'john@example.com';
      const updates = { name: 'John Doe' };
      const mockError = new Error('Database update error');

      mockUsersCollection.updateOne.mockRejectedValue(mockError);

      await expect(errsole.updateUserByEmail(email, updates)).rejects.toThrow('Database update error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: updates });
    });

    it('should handle database retrieval errors after update', async () => {
      const email = 'john@example.com';
      const updates = { name: 'John Doe' };
      const mockError = new Error('Database retrieval error');

      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockUsersCollection.findOne.mockRejectedValue(mockError);

      await expect(errsole.updateUserByEmail(email, updates)).rejects.toThrow('Database retrieval error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: updates });
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
    });

    it('should remove the hashed password from the updates if it exists', async () => {
      const email = 'john@example.com';
      const updates = { name: 'John Doe', hashed_password: 'new_hashed_password' };
      const updatedUser = {
        _id: new ObjectId(),
        name: 'John Doe',
        email: 'john@example.com',
        role: 'admin'
      };

      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockUsersCollection.findOne.mockResolvedValue(updatedUser);

      const result = await errsole.updateUserByEmail(email, updates);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: { name: 'John Doe' } });
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
      expect(result).toEqual({ item: { id: updatedUser._id.toString(), name: 'John Doe', email: 'john@example.com', role: 'admin' } });
    });

    it('should handle the case where the user does not exist', async () => {
      const email = 'nonexistent@example.com';
      const updates = { name: 'Nonexistent User' };

      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 0 });

      await expect(errsole.updateUserByEmail(email, updates)).rejects.toThrow('No updates applied. User record not found or provided updates are identical to existing data.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: updates });
    });

    it('should return the updated user data without _id if the update is successful', async () => {
      const email = 'john@example.com';
      const updates = { name: 'John Doe' };
      const updatedUser = {
        _id: new ObjectId(),
        name: 'John Doe',
        email: 'john@example.com',
        role: 'admin'
      };

      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });
      mockUsersCollection.findOne.mockResolvedValue(updatedUser);

      const result = await errsole.updateUserByEmail(email, updates);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith({ email }, { $set: updates });
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email }, { projection: { hashed_password: 0 } });
      expect(result).toEqual({ item: { id: updatedUser._id.toString(), name: 'John Doe', email: 'john@example.com', role: 'admin' } });
    });
  });

  describe('updatePassword', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');

      mockDb.collection.mockImplementation((name) => {
        if (name === 'errsole_users') {
          return mockUsersCollection;
        }
        return mockLogsCollection;
      });
    });

    it('should update the user password successfully', async () => {
      const email = 'john@example.com';
      const currentPassword = 'currentPassword';
      const newPassword = 'newPassword';
      const hashedPassword = 'hashed_password';
      const hashedNewPassword = 'new_hashed_password';
      const user = {
        _id: new ObjectId(),
        email,
        hashed_password: hashedPassword
      };
      const updatedUser = {
        ...user,
        hashed_password: hashedNewPassword
      };

      mockUsersCollection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);
      bcrypt.hash.mockResolvedValue(hashedNewPassword);
      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await errsole.updatePassword(email, currentPassword, newPassword);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
      expect(bcrypt.compare).toHaveBeenCalledWith(currentPassword, hashedPassword);
      expect(bcrypt.hash).toHaveBeenCalledWith(newPassword, expect.any(Number));
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email },
        { $set: { hashed_password: hashedNewPassword } }
      );

      const expectedUser = { ...user, id: user._id.toString() };
      delete expectedUser._id;
      delete expectedUser.hashed_password;

      expect(result).toEqual({ item: expectedUser });
    });

    it('should throw an error if user is not found', async () => {
      const email = 'nonexistent@example.com';
      const currentPassword = 'currentPassword';
      const newPassword = 'newPassword';

      mockUsersCollection.findOne.mockResolvedValue(null);

      await expect(errsole.updatePassword(email, currentPassword, newPassword)).rejects.toThrow('User not found.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
    });

    it('should throw an error if current password is incorrect', async () => {
      const email = 'john@example.com';
      const currentPassword = 'wrongPassword';
      const newPassword = 'newPassword';
      const hashedPassword = 'hashed_password';
      const user = {
        _id: new ObjectId(),
        email,
        hashed_password: hashedPassword
      };

      mockUsersCollection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(false);

      await expect(errsole.updatePassword(email, currentPassword, newPassword)).rejects.toThrow('Current password is incorrect.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
      expect(bcrypt.compare).toHaveBeenCalledWith(currentPassword, hashedPassword);
    });

    it('should throw an error if password update fails', async () => {
      const email = 'john@example.com';
      const currentPassword = 'currentPassword';
      const newPassword = 'newPassword';
      const hashedPassword = 'hashed_password';
      const hashedNewPassword = 'new_hashed_password';
      const user = {
        _id: new ObjectId(),
        email,
        hashed_password: hashedPassword
      };

      mockUsersCollection.findOne.mockResolvedValue(user);
      bcrypt.compare.mockResolvedValue(true);
      bcrypt.hash.mockResolvedValue(hashedNewPassword);
      mockUsersCollection.updateOne.mockResolvedValue({ modifiedCount: 0 });

      await expect(errsole.updatePassword(email, currentPassword, newPassword)).rejects.toThrow('Password update failed.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.findOne).toHaveBeenCalledWith({ email });
      expect(bcrypt.compare).toHaveBeenCalledWith(currentPassword, hashedPassword);
      expect(bcrypt.hash).toHaveBeenCalledWith(newPassword, expect.any(Number));
      expect(mockUsersCollection.updateOne).toHaveBeenCalledWith(
        { email },
        { $set: { hashed_password: hashedNewPassword } }
      );
    });
  });

  describe('deleteUser', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');

      mockDb.collection.mockImplementation((name) => {
        if (name === 'errsole_users') {
          return mockUsersCollection;
        }
        return mockLogsCollection;
      });
    });

    it('should delete a user successfully', async () => {
      const userId = new ObjectId().toString();

      mockUsersCollection.deleteOne.mockResolvedValue({ deletedCount: 1 });

      const result = await errsole.deleteUser(userId);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.deleteOne).toHaveBeenCalledWith({ _id: new ObjectId(userId) });
      expect(result).toEqual({});
    });

    it('should throw an error if user is not found', async () => {
      const userId = new ObjectId().toString();

      mockUsersCollection.deleteOne.mockResolvedValue({ deletedCount: 0 });

      await expect(errsole.deleteUser(userId)).rejects.toThrow('User not found.');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.deleteOne).toHaveBeenCalledWith({ _id: new ObjectId(userId) });
    });

    it('should handle database errors gracefully', async () => {
      const userId = new ObjectId().toString();
      const mockError = new Error('Database deletion error');

      mockUsersCollection.deleteOne.mockRejectedValue(mockError);

      await expect(errsole.deleteUser(userId)).rejects.toThrow('Database deletion error');

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_users');
      expect(mockUsersCollection.deleteOne).toHaveBeenCalledWith({ _id: new ObjectId(userId) });
    });
  });

  describe('updateLogsCollectionTTL', () => {
    it('should update the TTL index if it does not match the new TTL value', async () => {
      await errsole.updateLogsCollectionTTL(7200000);

      expect(mockLogsCollection.dropIndex).toHaveBeenCalledWith('timestamp_1');
      expect(mockLogsCollection.createIndex).toHaveBeenCalledWith({ timestamp: 1 }, { expireAfterSeconds: 7200 });
    });
  });

  describe('getHostnames', () => {
    let errsole;

    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
    });

    it('should return sorted hostnames excluding null or empty values', async () => {
      const mockHostnames = ['host1', 'host2', null, '', 'host3'];
      mockLogsCollection.distinct.mockResolvedValue(mockHostnames);

      const result = await errsole.getHostnames();

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.distinct).toHaveBeenCalledWith('hostname', { hostname: { $nin: [null, ''] } });

      const expectedHostnames = ['host1', 'host2', 'host3'];
      expect(result.items).toEqual(expectedHostnames);
    });

    it('should handle empty hostname list', async () => {
      mockLogsCollection.distinct.mockResolvedValue([]);

      const result = await errsole.getHostnames();

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.distinct).toHaveBeenCalledWith('hostname', { hostname: { $nin: [null, ''] } });
      expect(result.items).toEqual([]);
    });

    it('should handle errors during hostname retrieval and return the error', async () => {
      const mockError = new Error('Database error');
      mockLogsCollection.distinct.mockRejectedValue(mockError);

      const result = await errsole.getHostnames();

      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('Database error');
      expect(mockDb.collection).toHaveBeenCalledWith('errsole_logs_v2');
      expect(mockLogsCollection.distinct).toHaveBeenCalledWith('hostname', { hostname: { $nin: [null, ''] } });
    });
  });

  describe('insertNotificationItem', () => {
    it('should insert notification and return previous notification and todayNotificationCount', async () => {
      const notification = {
        errsole_id: 101,
        hostname: 'localhost',
        hashed_message: 'hashedMsg'
      };

      const mockPreviousNotification = { _id: 'prev_id', hostname: 'localhost', hashed_message: 'hashedMsg', created_at: new Date() };
      const mockInsertResult = { insertedId: new ObjectId() };

      mockLogsCollection.findOne.mockResolvedValue(mockPreviousNotification);
      mockLogsCollection.insertOne.mockResolvedValue(mockInsertResult);
      mockLogsCollection.countDocuments.mockResolvedValue(2);

      const result = await errsole.insertNotificationItem(notification);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_notifications');
      expect(mockLogsCollection.findOne).toHaveBeenCalledWith(
        { hostname: 'localhost', hashed_message: 'hashedMsg' },
        { sort: { created_at: -1 }, session: expect.any(Object) }
      );
      expect(mockLogsCollection.insertOne).toHaveBeenCalledWith(
        expect.objectContaining({
          errsole_id: 101,
          hostname: 'localhost',
          hashed_message: 'hashedMsg'
        }),
        { session: expect.any(Object) }
      );
      expect(mockLogsCollection.countDocuments).toHaveBeenCalledWith(
        {
          hostname: 'localhost',
          hashed_message: 'hashedMsg',
          created_at: expect.any(Object)
        },
        { session: expect.any(Object) }
      );
      expect(result).toEqual({
        previousNotificationItem: { id: 'prev_id', hostname: 'localhost', hashed_message: 'hashedMsg', created_at: mockPreviousNotification.created_at },
        todayNotificationCount: 2
      });
    });

    it('should throw an error if the transaction fails', async () => {
      const notification = {
        errsole_id: 101,
        hostname: 'localhost',
        hashed_message: 'hashedMsg'
      };

      const mockError = new Error('Transaction failed');
      mockLogsCollection.insertOne.mockRejectedValue(mockError);

      await expect(errsole.insertNotificationItem(notification)).rejects.toThrow('Transaction failed');
    });
  });

  describe('updateNotificationsCollectionTTL', () => {
    let errsole;
    let mockIndexes;
    beforeEach(() => {
      jest.clearAllMocks();
      errsole = new ErrsoleMongoDB('mongodb://localhost:27017', 'test_db');
      mockIndexes = [
        { name: 'created_at_1', key: { created_at: 1 }, expireAfterSeconds: 3600 }
      ];
      mockDb.collection.mockReturnValue({
        indexes: jest.fn().mockResolvedValue(mockIndexes),
        createIndex: jest.fn(),
        dropIndex: jest.fn()
      });
    });

    it('should drop the existing TTL index and create a new one if TTL differs', async () => {
      const notificationsTTL = 7200000;

      await errsole.updateNotificationsCollectionTTL(notificationsTTL);

      expect(mockDb.collection).toHaveBeenCalledWith('errsole_notifications');
      expect(mockDb.collection().dropIndex).toHaveBeenCalledWith('created_at_1');
      expect(mockDb.collection().createIndex).toHaveBeenCalledWith(
        { created_at: 1 },
        { expireAfterSeconds: 7200 }
      );
    });

    it('should create a new TTL index if no TTL index exists', async () => {
      mockIndexes = [];
      await errsole.updateNotificationsCollectionTTL(7200000); // 2 hours TTL
      expect(mockDb.collection().createIndex).toHaveBeenCalledWith(
        { created_at: 1 },
        { expireAfterSeconds: 7200 }
      );
    });
  });
});

const ErrsoleMongoDB = require('../../lib/index'); // Replace with the path to your index file
/* globals describe, it,  beforeAll, afterAll, expect */

describe('ErrsoleMongoDB', () => {
  let errsoleMongoDB;

  beforeAll(async () => {
    errsoleMongoDB = new ErrsoleMongoDB('mongodb://localhost:27017', 'jest_DB');
    try {
      await errsoleMongoDB.client.connect();
      await errsoleMongoDB.ensureCollections(); // Ensure collections are set up
    } catch (error) {
      console.error('Failed to connect to MongoDB:', error);
      throw error; // Rethrow to prevent further execution
    }
  });

  afterAll(async () => {
    await errsoleMongoDB.client.close();
  });

  describe('#createUser', () => {
    it('should create a new user', async () => {
      const user = {
        name: 'Peter Parker',
        email: 'peter@gmail.com',
        password: 'password123',
        role: 'admin'
      };
      const result = await errsoleMongoDB.createUser(user);
      expect(result.item).toHaveProperty('name', user.name);
      expect(result.item).toHaveProperty('email', user.email);
      expect(result.item).toHaveProperty('role', user.role);
    });
  });
  describe('#verifyUser', () => {
    it('should verify a user', async () => {
      const user = {
        email: 'peter@gmail.com',
        password: 'password123'
      };
      const result = await errsoleMongoDB.verifyUser(user.email, user.password);
      return result;
    });
  });

  describe('#getUserCount', () => {
    it('should get the count of users', async () => {
      const result = await errsoleMongoDB.getUserCount();
      return result;
    });
  });

  describe('#getAllUsers', () => {
    it('should get all users', async () => {
      const result = await errsoleMongoDB.getAllUsers();
      return result;
    });
  });

  describe('#setConfig', () => {
    it('should set a configuration entry', async () => {
      const key = 'JwtToken';
      const value = 'sdfnjcesjncfenjnjerfnf';
      const result = await errsoleMongoDB.setConfig(key, value);
      expect(result.item).toHaveProperty('key', key);
    });
  });

  describe('#getConfig', () => {
    it('should get a configuration entry', async () => {
      const key = 'JwtToken';
      const result = await errsoleMongoDB.getConfig(key);
      return result.value;
    });
  });

  describe('#setConfig', () => {
    it('should set a configuration entry', async () => {
      const key = 'JwtToken';
      const value = 'value';
      const result = await errsoleMongoDB.setConfig(key, value);
      expect(result.item).toHaveProperty('key', key);
    });
  });

  describe('#getConfig', () => {
    it('should get a configuration entry', async () => {
      const key = 'JwtToken';
      const result = await errsoleMongoDB.getConfig(key);
      return result.value;
    });
  });

  describe('#deleteConfig', () => {
    it('should delete a configuration entry', async () => {
      const key = 'JwtToken';
      const result = await errsoleMongoDB.deleteConfig(key);
      return result;
    });
  });

  describe('#getUserByEmail', () => {
    it('should get a user by email', async () => {
      const email = 'peter@gmail.com';
      const result = await errsoleMongoDB.getUserByEmail(email);
      return result.item;
    });
  });
  describe('#updateUserByEmail', () => {
    it('should update a user by email', async () => {
      const email = 'peter@gmail.com';
      const updates = { name: 'Peter smith' };
      const result = await errsoleMongoDB.updateUserByEmail(email, updates);
      return result.item;
    });
  });
});

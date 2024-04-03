# errsole-mongodb
A MongoDB logging module for Node.js applications, designed to simplify logging of information and errors to a MongoDB database. This module provides an easy way to log messages from your Node.js applications and retrieve them for monitoring or debugging purposes.

# Features
Easy integration with Node.js applications.
Configurable MongoDB connection.
Supports logging of information and error messages.
Provides a function to retrieve all logs from the database.

# installation
```
npm install errsole-mongodb
```

# usage
First, ensure you have MongoDB running and accessible from your application. Then, follow these steps to integrate errsole-mongodb into your Node.js application

# initialization
In your main application file, initialize the errsole-mongodb module with the MongoDB connection details:
```javascript
const errsoleMongoDB = require('errsole-mongodb');

const storage = new errsoleMongoDB(mongodb_url, database_name, options)
```

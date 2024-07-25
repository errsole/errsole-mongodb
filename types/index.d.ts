declare module 'errsole-mongodb' {
  import { MongoClientOptions } from 'mongodb';

  interface Log {
    id?: string;
    hostname: string;
    pid: number;
    source: string;
    timestamp: Date;
    level: string;
    message: string;
    meta?: string;
  }

  interface LogFilter {
    hostname?: string;
    pid?: number;
    level_json?: { source: string; level: string }[];
    sources?: string[];
    levels?: string[];
    lt_id?: string;
    gt_id?: string;
    lte_timestamp?: Date;
    gte_timestamp?: Date;
    limit?: number;
  }

  interface Config {
    id: string;
    key: string;
    value: string;
  }

  interface User {
    id: string;
    name: string;
    email: string;
    role: string;
  }

  class ErrsoleMongoDB {
    constructor(uri: string, dbNameOrOptions: string | MongoClientOptions, options?: MongoClientOptions);

    getConfig(key: string): Promise<{ item: Config }>;
    setConfig(key: string, value: string): Promise<{ item: Config }>;
    deleteConfig(key: string): Promise<{}>;

    postLogs(logEntries: Log[]): Promise<{}>;
    getLogs(filters?: LogFilter): Promise<{ items: Log[] }>;
    searchLogs(searchTerms: string[], filters?: LogFilter): Promise<{ items: Log[], filters: LogFilter[] }>;

    getMeta(id: string): Promise<{ item: { id: string; meta: string } }>;

    createUser(user: { name: string; email: string; password: string; role: string }): Promise<{ item: User }>;
    verifyUser(email: string, password: string): Promise<{ item: User }>;
    getUserCount(): Promise<{ count: number }>;
    getAllUsers(): Promise<{ items: User[] }>;
    getUserByEmail(email: string): Promise<{ item: User }>;
    updateUserByEmail(email: string, updates: Partial<User>): Promise<{ item: User }>;
    updatePassword(email: string, currentPassword: string, newPassword: string): Promise<{ item: User }>;
    deleteUser(id: string): Promise<{}>;
  }

  export default ErrsoleMongoDB;
}

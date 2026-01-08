import { uint8ArrayToHex } from '@xstd/hex';
import { Path, type PathInput } from '@xstd/path';
import { DatabaseSync, type StatementSync } from 'node:sqlite';

/* TYPES */

export interface AuthDatabaseGenerateTokenOptions {
  readonly name: string;
  readonly expiration?: number; // timestamp in seconds
  readonly rights: readonly string[];
}

export interface AuthDatabaseToken {
  readonly name: string;
  readonly expiration: number; // timestamp in seconds
  readonly token: string;
  readonly rights: readonly string[];
}

export type AuthDatabaseSafeToken = Omit<AuthDatabaseToken, 'token'>;

/* CLASS */

export class AuthDatabase {
  readonly #db: DatabaseSync;

  readonly #insertTokenStatement: StatementSync;
  readonly #insertRightStatement: StatementSync;
  readonly #selectTokenFromNameStatement: StatementSync;
  readonly #deleteTokenFromNameStatement: StatementSync;

  readonly #selectAllTokensStatement: StatementSync;
  readonly #selectRightsFromNameStatement: StatementSync;

  readonly #selectNotExpiredTokenFromTokenAndExpirationStatement: StatementSync;
  readonly #selectTokenFromTokenAndRightStatement: StatementSync;

  constructor(db: DatabaseSync | PathInput) {
    this.#db =
      db instanceof DatabaseSync
        ? db
        : new DatabaseSync(typeof db === 'string' ? db : Path.of(db).toString());

    this.#init();

    this.#selectTokenFromNameStatement = this.#db.prepare('SELECT name FROM tokens WHERE name = ?');
    this.#insertTokenStatement = this.#db.prepare(
      'INSERT INTO tokens (name, expiration, token) VALUES (?, ?, ?)',
    );
    this.#insertRightStatement = this.#db.prepare('INSERT INTO rights (name, right) VALUES (?, ?)');
    this.#deleteTokenFromNameStatement = this.#db.prepare('DELETE FROM tokens WHERE name = ?');

    this.#selectAllTokensStatement = this.#db.prepare('SELECT name, expiration FROM tokens');
    this.#selectRightsFromNameStatement = this.#db.prepare(
      'SELECT right FROM rights WHERE name = ?',
    );

    this.#selectNotExpiredTokenFromTokenAndExpirationStatement = this.#db.prepare(
      'SELECT name FROM tokens WHERE token = ? AND (expiration > ? OR expiration = 0)',
    );

    this.#selectTokenFromTokenAndRightStatement = this.#db.prepare(`
      SELECT name
      FROM rights
      WHERE name = (
        SELECT name FROM tokens WHERE token = ?
      )
      AND right = ?
    `);
  }

  #init(): void {
    this.#db.exec(`
      PRAGMA foreign_keys = ON;
  
      CREATE TABLE IF NOT EXISTS tokens(
        name TEXT NOT NULL PRIMARY KEY,
        expiration INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE
      ) STRICT;
    
      CREATE UNIQUE INDEX IF NOT EXISTS token_index ON tokens (token);
  
      CREATE TABLE IF NOT EXISTS rights(
        name TEXT NOT NULL,
        right TEXT NOT NULL,
        PRIMARY KEY (name, right)
        FOREIGN KEY (name)
          REFERENCES tokens (name)
            ON UPDATE RESTRICT
            ON DELETE CASCADE
      ) STRICT;
    `);
  }

  #getTokenRights({ name, expiration }: AuthDatabaseTokensRow): AuthDatabaseSafeToken {
    const rightsRows: readonly AuthDatabaseRightsRow[] = this.#selectRightsFromNameStatement.all(
      name,
    ) as unknown as readonly AuthDatabaseRightsRow[];

    return {
      name,
      expiration,
      rights: rightsRows.map(({ right }: AuthDatabaseRightsRow): string => right),
    };
  }

  generateToken({
    name,
    expiration = 0,
    rights,
  }: AuthDatabaseGenerateTokenOptions): AuthDatabaseToken {
    if (this.hasToken(name)) {
      throw new Error(`Token "${name}" already exists.`);
    }

    const token: string = `auth-${uint8ArrayToHex(crypto.getRandomValues(new Uint8Array(32)))}`;

    this.#insertTokenStatement.run(name, expiration, token);

    for (const right of rights) {
      this.#insertRightStatement.run(name, right);
    }

    return {
      name,
      expiration,
      token,
      rights,
    };
  }

  hasToken(name: string): boolean {
    return this.#selectTokenFromNameStatement.get(name) !== undefined;
  }

  getToken(name: string): AuthDatabaseSafeToken {
    const token: AuthDatabaseSafeToken | undefined = this.getOptionalToken(name);

    if (token === undefined) {
      throw new Error(`Token "${name}" does not exist.`);
    }

    return token;
  }

  getOptionalToken(name: string): AuthDatabaseSafeToken | undefined {
    const tokensRow: AuthDatabaseTokensRow | undefined = this.#db
      .prepare('SELECT name, expiration FROM tokens WHERE name = ?')
      .get(name) as AuthDatabaseTokensRow | undefined;

    if (tokensRow === undefined) {
      return undefined;
    }

    return this.#getTokenRights(tokensRow);
  }

  deleteToken(name: string): boolean {
    return this.#deleteTokenFromNameStatement.run(name).changes > 0;
  }

  listTokens(): AuthDatabaseSafeToken[] {
    return (
      this.#selectAllTokensStatement.all() as unknown as readonly AuthDatabaseTokensRow[]
    ).map((tokensRow: AuthDatabaseTokensRow): AuthDatabaseSafeToken => {
      return this.#getTokenRights(tokensRow);
    });
  }

  /* VERIFY */

  verifyTokenValidity(token: string): boolean {
    return (
      this.#selectNotExpiredTokenFromTokenAndExpirationStatement.get(
        token,
        Math.floor(Date.now() / 1000),
      ) !== undefined
    );
  }

  verifyTokenRight(token: string, right: string): boolean {
    return this.#selectTokenFromTokenAndRightStatement.get(token, right) !== undefined;
  }
}

/* INTERNAL TYPES */

interface AuthDatabaseTokensRow {
  readonly name: string;
  readonly expiration: number; // timestamp in seconds
  readonly token: string;
}

interface AuthDatabaseRightsRow {
  readonly name: string;
  readonly right: string;
}

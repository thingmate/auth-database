import { uint8ArrayToHex } from '@xstd/hex';
import { Path, type PathInput } from '@xstd/path';
import { DatabaseSync, type StatementSync } from 'node:sqlite';

/* TYPES */

/**
 * The options for generating a new token.
 */
export interface AuthDatabaseGenerateTokenOptions {
  /**
   * The name of the token. Must not already exist in the database.
   */
  readonly name: string;

  /**
   * The expiration date of the token as Unix Timestamp in seconds. A value of `0` means "no expiration". Defaults to `0` (no expiration).
   */
  readonly expiration?: number;

  /**
   * A list of rights to associate with the token: it may be any string value.
   */
  readonly rights: readonly string[];
}

/**
 * A token with its unique and private token value.
 */
export interface AuthDatabaseToken {
  /**
   * The unique name of the token.
   */
  readonly name: string;

  /**
   * The expiration date of the token as Unix Timestamp in seconds.
   */
  readonly expiration: number;

  /**
   * The token's value: this is the key that must be safely stored elsewhere and used to authenticate the caller and compare against rights.
   */
  readonly token: string;

  /**
   * The rights associated with the token.
   */
  readonly rights: readonly string[];
}

/**
 * A token without its token value: the token's value is only available upon generation and must be stored securely by the caller.
 */
export type AuthDatabaseSafeToken = Omit<AuthDatabaseToken, 'token'>;

/* CLASS */

/**
 * A simple database to store tokens and rights.
 *
 * @example: create a unique token and use it as an API authentication method
 *
 * ```ts
 * // 1) Create an Auth DB
 * const db = new AuthDatabase(':memory:');
 *
 * // 2) (done only once) - Generate a token, and provide it as a Bearer token in the request header
 * const token = db.generateToken({
 *   name: 'my-token',
 *   expiration: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365, // 1 year
 *   rights: ['read', 'write'],
 * });
 *
 * // 3) When the server receives a request, we verify the token validity and rights
 * function verifyApiReadAccess(request: Request): void {
 *   const authorization: string | null = request.headers.get('Authorization');
 *
 *   if (authorization === null) {
 *     throw new Error('Missing Authorization header');
 *   }
 *
 *   if (!authorization.startsWith('Bearer ')) {
 *     throw new Error('Invalid Authorization header. Expected "Bearer <token>" format.');
 *   }
 *
 *   const token: string = authorization.slice('Bearer '.length);
 *
 *   if (!db.verifyTokenValidity(token) || !db.verifyTokenRight(token, 'read')) {
 *     throw new Error('Invalid token or insufficient rights.');
 *   }
 * }
 *
 * // request example:
 * fetch('https://api.example.com/resource', {
 *   headers: { Authorization: `Bearer ${token.token}` },
 * });
 * ```
 */
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

  /**
   * Constructs an instance of the class to manage tokens and rights.
   *
   * @param {DatabaseSync | PathInput} db A database instance (`DatabaseSync`) or the path to the database.
   */
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

  /**
   * Initializes the database schema.
   */
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

  /**
   * Gets the rights associated with a _partial_ token (`AuthDatabaseTokensRow`) and returns a _complete_ token object (`AuthDatabaseSafeToken`).
   */
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

  /**
   * Generates a new authentication token and stores it in the database along with its associated rights.
   *
   * @param {AuthDatabaseGenerateTokenOptions} options The options for generating the token.
   * @param {string} options.name The unique name of the token. Must not already exist in the database.
   * @param {number} [options.expiration] The expiration date of the token as Unix Timestamp in seconds. A value of `0` means "no expiration". Defaults to `0` (no expiration).
   * @param {readonly string[]} options.rights A list of rights to associate with the token.
   * @returns {AuthDatabaseToken} The generated token object containing the token details. The `token` property is only available upon generation and must be stored securely by the caller.
   * @throws {Error} If a token with the specified name already exists.
   *
   * @example:
   *
   * ```ts
   * const token = authDatabase.generateToken({
   *   name: 'my-token',
   *   expiration: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365, // 1 year
   *   rights: ['read', 'write'],
   * });
   * ```
   */
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

  /**
   * Checks if a token with the specified name exists.
   *
   * @param {string} name The name of the token to check.
   * @returns {boolean} Returns true if the token exists, otherwise false.
   */
  hasToken(name: string): boolean {
    return this.#selectTokenFromNameStatement.get(name) !== undefined;
  }

  /**
   * Retrieves an authentication token by its name.
   *
   * @param {string} name The name of the token to retrieve.
   * @returns {AuthDatabaseSafeToken} The authentication token associated with the specified name.
   * @throws {Error} An error if the token does not exist.
   */
  getToken(name: string): AuthDatabaseSafeToken {
    const token: AuthDatabaseSafeToken | undefined = this.getOptionalToken(name);

    if (token === undefined) {
      throw new Error(`Token "${name}" does not exist.`);
    }

    return token;
  }

  /**
   * Retrieves an optional authentication token by its name from the database.
   *
   * @param {string} name The name of the token to retrieve.
   * @returns {AuthDatabaseSafeToken | undefined} The token object if it exists, or undefined if not found.
   */
  getOptionalToken(name: string): AuthDatabaseSafeToken | undefined {
    const tokensRow: AuthDatabaseTokensRow | undefined = this.#db
      .prepare('SELECT name, expiration FROM tokens WHERE name = ?')
      .get(name) as AuthDatabaseTokensRow | undefined;

    if (tokensRow === undefined) {
      return undefined;
    }

    return this.#getTokenRights(tokensRow);
  }

  /**
   * Deletes a token identified by its name.
   *
   * @param {string} name The name of the token to be deleted.
   * @returns {boolean} Returns `true` if the token was successfully deleted, otherwise `false`.
   */
  deleteToken(name: string): boolean {
    return this.#deleteTokenFromNameStatement.run(name).changes > 0;
  }

  /**
   * Retrieves a list of tokens from the database into a safe format suitable for use.
   *
   * @returns {AuthDatabaseSafeToken[]} The list of all the tokens.
   */
  listTokens(): AuthDatabaseSafeToken[] {
    return (
      this.#selectAllTokensStatement.all() as unknown as readonly AuthDatabaseTokensRow[]
    ).map((tokensRow: AuthDatabaseTokensRow): AuthDatabaseSafeToken => {
      return this.#getTokenRights(tokensRow);
    });
  }

  /* VERIFY */

  /**
   * Verifies the validity of a given token by checking if it exists and is not expired.
   *
   * @param {string} token - The token to be validated.
   * @returns {boolean} Returns true if the token is valid and not expired, otherwise false.
   */
  verifyTokenValidity(token: string): boolean {
    return (
      this.#selectNotExpiredTokenFromTokenAndExpirationStatement.get(
        token,
        Math.floor(Date.now() / 1000),
      ) !== undefined
    );
  }

  /**
   * Verifies if the provided token and right combination exists.
   *
   * @param {string} token The token to verify.
   * @param {string} right The right associated with the token to verify.
   * @returns {boolean} Returns true if the token and right combination exists, otherwise false.
   */
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

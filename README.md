[![npm (scoped)](https://img.shields.io/npm/v/@thingmate/auth-database.svg)](https://www.npmjs.com/package/@thingmate/auth-database)
![npm](https://img.shields.io/npm/dm/@thingmate/auth-database.svg)
![NPM](https://img.shields.io/npm/l/@thingmate/auth-database.svg)
![npm type definitions](https://img.shields.io/npm/types/@thingmate/auth-database.svg)

## @thingmate/auth-database

A simple Auth database implementation to store tokens and rights.

## 📦 Installation

```shell
yarn add @thingmate/auth-database
# or
npm install @thingmate/auth-database --save
```

## ✍️ Examples

#### 1) Create an Auth database

```ts
const db = new AuthDatabase(':memory:');
```

#### 2) Generate a token

```ts
const { token } = db.generateToken({
  name: 'my-token',
  expiration: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365, // 1 year
  rights: ['read', 'write'],
});
```

Then we may store the `token` into Postman, a `.env` file, CI environement variables, etc. and use it as a Bearer token.

#### 3) Verify if a client has access to a specific API endpoint

```ts
function verifyApiReadAccess(request: Request): void {
  const authorization: string | null = request.headers.get('Authorization');

  if (authorization === null) {
    throw new Error('Missing Authorization header');
  }

  if (!authorization.startsWith('Bearer ')) {
    throw new Error('Invalid Authorization header. Expected "Bearer <token>" format.');
  }

  const token: string = authorization.slice('Bearer '.length);

  if (!db.verifyTokenValidity(token) || !db.verifyTokenRight(token, 'read')) {
    throw new Error('Invalid token or insufficient rights.');
  }
}
```

On the server side, when a client performs an HTTP request on a specific API endpoint, we can use the `Authorization` header to verify the token validity and rights.

#### 4) Performs an HTTP call on a protected API endpoint

```ts
fetch('https://api.example.com/resource', {
  headers: { Authorization: `Bearer ${env.TOKEN}` },
});
```

The client will now be able to perform an HTTP request on the protected API endpoint.

## 📜 Documentation

```ts
declare class AuthDatabase {
  /**
   * Constructs an instance of the class to manage tokens and rights.
   *
   * @param {DatabaseSync | PathInput} db A database instance (`DatabaseSync`) or the path to the database.
   */
  constructor(db: DatabaseSync | PathInput);

  /**
   * Generates a new authentication token and stores it in the database along with its associated rights.
   *
   * @param {AuthDatabaseGenerateTokenOptions} options The options for generating the token.
   * @param {string} options.name The unique name of the token. Must not already exist in the database.
   * @param {number} [options.expiration] The expiration date of the token as Unix Timestamp in seconds. A value of `0` means "no expiration". Defaults to `0` (no expiration).
   * @param {readonly string[]} options.rights A list of rights to associate with the token.
   * @returns {AuthDatabaseToken} The generated token object containing the token details. The `token` property is only available upon generation and must be stored securely by the caller.
   * @throws {Error} If a token with the specified name already exists.
   */
  generateToken({ name, expiration, rights, }: AuthDatabaseGenerateTokenOptions): AuthDatabaseToken;

  /**
   * Checks if a token with the specified name exists.
   *
   * @param {string} name The name of the token to check.
   * @returns {boolean} Returns true if the token exists, otherwise false.
   */
  hasToken(name: string): boolean;

  /**
   * Retrieves an authentication token by its name.
   *
   * @param {string} name The name of the token to retrieve.
   * @returns {AuthDatabaseSafeToken} The authentication token associated with the specified name.
   * @throws {Error} An error if the token does not exist.
   */
  getToken(name: string): AuthDatabaseSafeToken;

  /**
   * Retrieves an optional authentication token by its name from the database.
   *
   * @param {string} name The name of the token to retrieve.
   * @returns {AuthDatabaseSafeToken | undefined} The token object if it exists, or undefined if not found.
   */
  getOptionalToken(name: string): AuthDatabaseSafeToken | undefined;

  /**
   * Deletes a token identified by its name.
   *
   * @param {string} name The name of the token to be deleted.
   * @returns {boolean} Returns `true` if the token was successfully deleted, otherwise `false`.
   */
  deleteToken(name: string): boolean;

  /**
   * Retrieves a list of tokens from the database into a safe format suitable for use.
   *
   * @returns {AuthDatabaseSafeToken[]} The list of all the tokens.
   */
  listTokens(): AuthDatabaseSafeToken[];

  /**
   * Verifies the validity of a given token by checking if it exists and is not expired.
   *
   * @param {string} token - The token to be validated.
   * @returns {boolean} Returns true if the token is valid and not expired, otherwise false.
   */
  verifyTokenValidity(token: string): boolean;

  /**
   * Verifies if the provided token and right combination exists.
   *
   * @param {string} token The token to verify.
   * @param {string} right The right associated with the token to verify.
   * @returns {boolean} Returns true if the token and right combination exists, otherwise false.
   */
  verifyTokenRight(token: string, right: string): boolean;
}

```

```ts
/**
 * The options for generating a new token.
 */
interface AuthDatabaseGenerateTokenOptions {
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
interface AuthDatabaseToken {
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
type AuthDatabaseSafeToken = Omit<AuthDatabaseToken, 'token'>;
```

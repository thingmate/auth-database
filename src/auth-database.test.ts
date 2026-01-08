import { Path } from '@xstd/path';
import { rm } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuthDatabase, type AuthDatabaseToken } from './auth-database.ts';

describe('AuthDatabase', () => {
  describe('constructor', () => {
    it('should support in memory db', () => {
      const db = new AuthDatabase(':memory:');
      expect(db).toBeDefined();
    });

    it('should support DatabaseSync db', () => {
      const db = new AuthDatabase(new DatabaseSync(':memory:'));
      expect(db).toBeDefined();
    });

    it('should support Path', async () => {
      const path = new Path('./tmp.db');
      try {
        const db = new AuthDatabase(path);
        expect(db).toBeDefined();
      } finally {
        await rm(path.toString());
      }
    });
  });

  describe('members', () => {
    let db: AuthDatabase;

    beforeEach(() => {
      db = new AuthDatabase(':memory:');
    });

    describe('methods', () => {
      describe('generateToken', () => {
        it('should generate a new token', () => {
          const token: AuthDatabaseToken = db.generateToken({ name: 'test', rights: ['read'] });

          expect(token.name).toBe('test');
          expect(token.token).toBeDefined();
        });

        it('should prevent the creation of duplicate tokens', () => {
          expect(db.generateToken({ name: 'test', rights: ['read'] })).toBeDefined();
          expect(() => db.generateToken({ name: 'test', rights: ['read'] })).toThrow();
        });
      });

      describe('hasToken', () => {
        it('should have expected token', () => {
          db.generateToken({ name: 'test', rights: ['read'] });
          expect(db.hasToken('test')).toBe(true);
        });

        it('should not have unexpected token', () => {
          expect(db.hasToken('test')).toBe(false);
        });
      });

      describe('getToken', () => {
        it('should return expected token', () => {
          db.generateToken({ name: 'test', rights: ['read'] });
          expect(db.getToken('test').rights).toEqual(['read']);
        });

        it('should throw if token does not exists', () => {
          expect(() => db.getToken('test')).toThrow();
        });
      });

      describe('getOptionalToken', () => {
        it('should return expected token', () => {
          db.generateToken({ name: 'test', rights: ['read'] });
          expect(db.getOptionalToken('test')?.rights).toEqual(['read']);
        });

        it('should return undefined if token does not exists', () => {
          expect(db.getOptionalToken('test')).toBe(undefined);
        });
      });

      describe('getOptionalToken', () => {
        it('should delete token', () => {
          expect(db.hasToken('test')).toBe(false);
          expect(db.deleteToken('test')).toBe(false);

          db.generateToken({ name: 'test', rights: ['read'] });
          expect(db.hasToken('test')).toBe(true);

          expect(db.deleteToken('test')).toBe(true);
          expect(db.hasToken('test')).toBe(false);
        });
      });

      describe('listTokens', () => {
        it('should list tokens', () => {
          expect(db.listTokens()).toEqual([]);

          db.generateToken({ name: 'test', rights: ['read'] });

          expect(db.listTokens()).toEqual([
            {
              expiration: 0,
              name: 'test',
              rights: ['read'],
            },
          ]);
        });
      });

      describe('verifyTokenValidity', () => {
        it('should return true for never expiring token', () => {
          const { token } = db.generateToken({ name: 'test', rights: ['read'] });

          expect(db.verifyTokenValidity(token)).toBe(true);
        });

        it('should return true for future token', () => {
          const { token } = db.generateToken({
            name: 'test',
            rights: ['read'],
            expiration: Math.floor(Date.now() / 1000) + 60,
          });

          expect(db.verifyTokenValidity(token)).toBe(true);
        });

        it('should return false for past token', () => {
          const { token } = db.generateToken({
            name: 'test',
            rights: ['read'],
            expiration: Math.floor(Date.now() / 1000) - 60,
          });

          expect(db.verifyTokenValidity(token)).toBe(false);
        });

        it('should return false for inexisting token', () => {
          expect(db.verifyTokenValidity('invalid')).toBe(false);
        });
      });

      describe('verifyTokenRight', () => {
        it('should return true if token has expected right', () => {
          const { token } = db.generateToken({ name: 'test', rights: ['read'] });

          expect(db.verifyTokenRight(token, 'read')).toBe(true);
        });

        it('should return false if token does not gave expected right', () => {
          const { token } = db.generateToken({ name: 'test', rights: ['read'] });

          expect(db.verifyTokenRight(token, 'write')).toBe(false);
        });

        it('should return false for inexisting token', () => {
          expect(db.verifyTokenRight('invalid', 'read')).toBe(false);
        });
      });
    });
  });
});

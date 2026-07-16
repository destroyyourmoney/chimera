// Pure logic tests for account_store.dart: key normalization/validation
// (must agree byte-for-byte with internal/controlplane's Go-side alphabet,
// see account_store.dart's keyAlphabet doc comment) and AccountInfo's JSON
// round-trip. HTTP calls (redeem/refresh/AccountStore.load's file I/O)
// aren't covered here -- same rationale as settings_store_test.dart's doc
// comment: no platform channel worth mocking for what's essentially a thin
// wrapper, the branching logic worth testing is normalization/validation.
import 'package:chimera_tray/account_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('normalizeAccountNumber', () {
    test('uppercases and groups a bare 16-char string', () {
      expect(normalizeAccountNumber('7k2m9pqr4tzsxw3h'), '7K2M-9PQR-4TZS-XW3H');
    });

    test('is idempotent on an already-grouped key', () {
      expect(normalizeAccountNumber('7K2M-9PQR-4TZS-XW3H'), '7K2M-9PQR-4TZS-XW3H');
    });

    test('strips stray whitespace', () {
      expect(normalizeAccountNumber(' 7K2M 9PQR 4TZS XW3H '), '7K2M-9PQR-4TZS-XW3H');
    });

    test('handles partial input without throwing (in-progress typing)', () {
      expect(normalizeAccountNumber('7K2'), '7K2');
      expect(normalizeAccountNumber(''), '');
    });
  });

  group('isValidAccountNumber', () {
    test('accepts a well-formed key', () {
      expect(isValidAccountNumber('7K2M-9PQR-4TZS-XW3H'), isTrue);
    });

    test('rejects wrong length', () {
      expect(isValidAccountNumber('7K2M-9PQR-4TZS'), isFalse);
      expect(isValidAccountNumber('7K2M-9PQR-4TZS-XW3H-EXTRA'), isFalse);
    });

    test('rejects excluded characters 0/O/1/I (Crockford minus confusables)', () {
      // '0', 'O', '1', 'I' are all deliberately absent from the alphabet
      // (ROADMAP2 §1) -- a key containing any of them can't be a real one.
      expect(isValidAccountNumber('0000-0000-0000-0000'), isFalse);
      expect(isValidAccountNumber('OOOO-OOOO-OOOO-OOOO'), isFalse);
      expect(isValidAccountNumber('1111-1111-1111-1111'), isFalse);
      expect(isValidAccountNumber('IIII-IIII-IIII-IIII'), isFalse);
    });

    test('rejects lowercase (normalize first)', () {
      expect(isValidAccountNumber('7k2m-9pqr-4tzs-xw3h'), isFalse);
    });

    test('rejects missing hyphens', () {
      expect(isValidAccountNumber('7K2M9PQR4TZSXW3H'), isFalse);
    });
  });

  group('AccountInfo', () {
    test('round-trips through JSON', () {
      final info = AccountInfo(
        numberMasked: '•••• •••• •••• XW3H',
        status: AccountStatus.active,
        expiresAt: DateTime.utc(2027, 1, 1),
        deviceCount: 2,
        deviceLimit: 5,
        token: 'abc.def',
        tokenIssuedAt: DateTime.utc(2026, 6, 1),
      );
      final decoded = AccountInfo.fromJson(info.toJson());
      expect(decoded.numberMasked, info.numberMasked);
      expect(decoded.status, AccountStatus.active);
      expect(decoded.expiresAt, info.expiresAt);
      expect(decoded.deviceCount, 2);
      expect(decoded.deviceLimit, 5);
      expect(decoded.token, 'abc.def');
      expect(decoded.tokenIssuedAt, info.tokenIssuedAt);
    });

    test('tokenExpired is false right after issuance', () {
      final info = AccountInfo(
        numberMasked: 'x',
        status: AccountStatus.active,
        expiresAt: DateTime.now().add(const Duration(days: 1)),
        deviceCount: 1,
        deviceLimit: 5,
        token: 't',
        tokenIssuedAt: DateTime.now(),
      );
      expect(info.tokenExpired, isFalse);
    });

    test('tokenExpired is true after the 24h TTL', () {
      final info = AccountInfo(
        numberMasked: 'x',
        status: AccountStatus.active,
        expiresAt: DateTime.now().add(const Duration(days: 1)),
        deviceCount: 1,
        deviceLimit: 5,
        token: 't',
        tokenIssuedAt: DateTime.now().subtract(const Duration(hours: 25)),
      );
      expect(info.tokenExpired, isTrue);
    });

    test('copyWith overrides only the given fields', () {
      final info = AccountInfo(
        numberMasked: 'x',
        status: AccountStatus.active,
        expiresAt: DateTime.utc(2027, 1, 1),
        deviceCount: 1,
        deviceLimit: 5,
        token: 't',
        tokenIssuedAt: DateTime.utc(2026, 1, 1),
      );
      final updated = info.copyWith(deviceCount: 3, status: AccountStatus.revoked);
      expect(updated.deviceCount, 3);
      expect(updated.status, AccountStatus.revoked);
      // Untouched fields carry over.
      expect(updated.numberMasked, 'x');
      expect(updated.token, 't');
    });
  });
}

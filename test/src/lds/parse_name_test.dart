import 'package:dmrtd/src/lds/parse_name.dart';
import 'package:test/test.dart';

void main() {
  group('ParseName', () {
    test('should handle empty list', () {
      final parser = ParseName([]);
      expect(parser.firstName, equals(''));
      expect(parser.lastName, equals(''));
    });

    test('should handle single name', () {
      final parser = ParseName(['John']);
      expect(parser.firstName, equals('John'));
      expect(parser.lastName, equals(''));
    });

    test('should handle two names', () {
      final parser = ParseName(['Doe', 'John']);
      expect(parser.firstName, equals('John'));
      expect(parser.lastName, equals('Doe'));
    });

    test('should handle multiple names', () {
      final parser = ParseName(['Smith', 'John', 'Paul']);
      expect(parser.firstName, equals('John Paul'));
      expect(parser.lastName, equals('Smith'));
    });

    test('should handle single name with space', () {
      final parser = ParseName(['Van Der Meer bin Bakar']);
      expect(parser.firstName, equals('Van Der Meer bin Bakar'));
      expect(parser.lastName, equals(''));
    });

    test('should handle two names with space', () {
      final parser = ParseName(['Van Der Meer', 'Louis']);
      expect(parser.firstName, equals('Louis'));
      expect(parser.lastName, equals('Van Der Meer'));
    });

    test('should handle multiple names with space', () {
      final parser = ParseName(['Doe', 'Smith', 'Van Der Meer']);
      expect(parser.firstName, equals('Smith Van Der Meer'));
      expect(parser.lastName, equals('Doe'));
    });

    test('should handle multiple names with space in each name', () {
      final parser = ParseName(['Jane Doe', 'Da Smith', 'Van Der Meer']);
      expect(parser.firstName, equals('Da Smith Van Der Meer'));
      expect(parser.lastName, equals('Jane Doe'));
    });

    test('should handle multiple names lastname with space, middle name and name', () {
      final parser = ParseName(["THEPHASADIN NA AYUTAYA", "PANIDA", "TON NAM"]);
      expect(parser.firstName, equals('PANIDA TON NAM'));
      expect(parser.lastName, equals('THEPHASADIN NA AYUTAYA'));
    });
  });
}

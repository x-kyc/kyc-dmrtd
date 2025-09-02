class ParseName {
  String firstName = '';
  String lastName = '';

  ParseName(List<String> nameIds) {
    if (nameIds.isEmpty) return;

    if (nameIds.length == 1) {
      firstName = nameIds[0];
      lastName = '';

      return;
    }

    lastName = nameIds[0];
    firstName = nameIds.sublist(1).join(' ');
  }
}

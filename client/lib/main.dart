import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(
    ByteLockerApp(
      allowLocalHttp:
          kDebugMode &&
          const bool.fromEnvironment(
            'PM_ALLOW_LOCAL_HTTP',
            defaultValue: false,
          ),
    ),
  );
}

import 'package:flutter/material.dart';

class ByteLockerLogo extends StatelessWidget {
  const ByteLockerLogo({super.key, this.size = 40});
  final double size;
  @override
  Widget build(BuildContext context) => ClipRRect(
    borderRadius: BorderRadius.circular(size * .18),
    child: Image.asset(
      'assets/brand/bytelocker.png',
      width: size,
      height: size,
      semanticLabel: 'Logo ByteLocker',
    ),
  );
}

class ByteLockerTitle extends StatelessWidget {
  const ByteLockerTitle({super.key});
  @override
  Widget build(BuildContext context) => const Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      ByteLockerLogo(size: 32),
      SizedBox(width: 10),
      Flexible(
        child: Text('ByteLocker', maxLines: 1, overflow: TextOverflow.ellipsis),
      ),
    ],
  );
}

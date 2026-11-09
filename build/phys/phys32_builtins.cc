extern "C" unsigned long long __udivdi3(unsigned long long dividend, unsigned long long divisor) {
  if (divisor == 0) {
    return 0;
  }

  unsigned long long quotient = 0;
  unsigned long long bit = 1;
  while ((divisor << 1) > divisor && (divisor << 1) <= dividend) {
    divisor <<= 1;
    bit <<= 1;
  }

  while (bit != 0) {
    if (dividend >= divisor) {
      dividend -= divisor;
      quotient |= bit;
    }
    divisor >>= 1;
    bit >>= 1;
  }

  return quotient;
}

extern "C" unsigned long long __umoddi3(unsigned long long dividend, unsigned long long divisor) {
  if (divisor == 0) {
    return 0;
  }

  unsigned long long bit = 1;
  while ((divisor << 1) > divisor && (divisor << 1) <= dividend) {
    divisor <<= 1;
    bit <<= 1;
  }

  while (bit != 0) {
    if (dividend >= divisor) {
      dividend -= divisor;
    }
    divisor >>= 1;
    bit >>= 1;
  }

  return dividend;
}

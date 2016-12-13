/* AUTOGENERATED FILE. DO NOT EDIT. */

//=======Test Runner Used To Run Each Test Below=====
#define RUN_TEST(TestFunc, TestLineNum) \
{ \
  Unity.CurrentTestName = #TestFunc; \
  Unity.CurrentTestLineNumber = TestLineNum; \
  Unity.NumberOfTests++; \
  if (TEST_PROTECT()) \
  { \
      setUp(); \
      TestFunc(); \
  } \
  if (TEST_PROTECT() && !TEST_IS_IGNORED) \
  { \
    tearDown(); \
  } \
  UnityConcludeTest(); \
}

//=======Automagically Detected Files To Include=====
#include "unity.h"
#include <setjmp.h>
#include <stdio.h>
#include "config.h"
#include "ntp_stdlib.h"
#include "ntp_fp.h"
#include <float.h>
#include <math.h>

//=======External Functions This Runner Calls=====
extern void setUp(void);
extern void tearDown(void);
extern void test_AdditionLR(void);
extern void test_AdditionRL(void);
extern void test_SubtractionLR(void);
extern void test_SubtractionRL(void);
extern void test_Negation(void);
extern void test_Absolute(void);
extern void test_FDF_RoundTrip(void);
extern void test_SignedRelOps(void);
extern void test_UnsignedRelOps(void);


//=======Test Reset Option=====
void resetTest(void);
void resetTest(void)
{
  tearDown();
  setUp();
}

char const *progname;


//=======MAIN=====
int main(int argc, char *argv[])
{
  progname = argv[0];
  UnityBegin("lfpfunc.c");
  RUN_TEST(test_AdditionLR, 48);
  RUN_TEST(test_AdditionRL, 49);
  RUN_TEST(test_SubtractionLR, 50);
  RUN_TEST(test_SubtractionRL, 51);
  RUN_TEST(test_Negation, 52);
  RUN_TEST(test_Absolute, 53);
  RUN_TEST(test_FDF_RoundTrip, 54);
  RUN_TEST(test_SignedRelOps, 55);
  RUN_TEST(test_UnsignedRelOps, 56);

  return (UnityEnd());
}

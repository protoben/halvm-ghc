# safeInfered tests are for testing that the Safe Haskell
# mode safe inference works correctly.

# Just do the normal way, SafeHaskell is all in the frontend
def f( name, opts ):
  opts.only_ways = ['normal']

setTestOpts(f)

# Tests that should compile fine as they should be infered safe
test('SafeInfered01',
     [ extra_clean(['SafeInfered01_A.hi', 'SafeInfered01_A.o']) ],
     multimod_compile, ['SafeInfered01', ''])
test('SafeInfered02',
     [ extra_clean(['SafeInfered02_A.hi', 'SafeInfered02_A.o']) ],
     multimod_compile, ['SafeInfered02', ''])
test('SafeInfered03',
     [ extra_clean(['SafeInfered03_A.hi', 'SafeInfered03_A.o']) ],
      multimod_compile, ['SafeInfered03', ''])
test('SafeInfered04',
     [ extra_clean(['SafeInfered04_A.hi', 'SafeInfered04_A.o']) ],
     multimod_compile, ['SafeInfered04', ''])
test('SafeInfered05',
     [ extra_clean(['SafeInfered05_A.hi', 'SafeInfered05_A.o']) ],
     multimod_compile, ['SafeInfered05', ''])

# Tests that should fail to compile as they should be infered unsafe
test('UnsafeInfered01',
     [ extra_clean(['UnsafeInfered01_A.hi', 'UnsafeInfered01_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered01', ''])
test('UnsafeInfered02',
     [ extra_clean(['UnsafeInfered02_A.hi', 'UnsafeInfered02_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered02', ''])
test('UnsafeInfered03',
     [ extra_clean(['UnsafeInfered03_A.hi', 'UnsafeInfered03_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered03', ''])
test('UnsafeInfered05',
     [ extra_clean(['UnsafeInfered05_A.hi', 'UnsafeInfered05_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered05', ''])
test('UnsafeInfered06',
     [ extra_clean(['UnsafeInfered06_A.hi', 'UnsafeInfered06_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered06', ''])
test('UnsafeInfered08',
     [ extra_clean(['UnsafeInfered08_A.hi', 'UnsafeInfered08_A.o']) ],
     multimod_compile, ['UnsafeInfered08', ''])
test('UnsafeInfered09',
     [ extra_clean(['UnsafeInfered09_A.hi', 'UnsafeInfered09_A.o',
                    'UnsafeInfered09_B.hi', 'UnsafeInfered09_B.o']) ],
     multimod_compile_fail, ['UnsafeInfered09', ''])

# Test that should fail as we disable safe inference
test('UnsafeInfered10',
     [ extra_clean(['UnsafeInfered10_A.hi', 'UnsafeInfered10_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered10', ''])
test('UnsafeInfered11',
     [ extra_clean(['UnsafeInfered11_A.hi', 'UnsafeInfered11_A.o']) ],
     multimod_compile_fail, ['UnsafeInfered11', ''])

# Test TH is unsafe
test('UnsafeInfered12', normal, compile_fail, [''])

# Test various overlapping instance flags
# GHC 7.10 and earlier we regarded them as unsafe, but we now take an approach
# based on looking only at sites of actual overlaps
test('UnsafeInfered13', normal, compile, [''])
test('UnsafeInfered14', normal, compile, [''])
test('UnsafeInfered15', normal, compile, [''])
test('UnsafeInfered16', normal, compile, [''])
test('UnsafeInfered17', normal, compile, [''])
test('UnsafeInfered18', normal, compile, [''])
test('UnsafeInfered19', normal, compile, [''])

# Mixed tests
test('Mixed01', normal, compile_fail, [''])
test('Mixed02', normal, compile_fail, [''])
test('Mixed03', normal, compile_fail, [''])

# Trustworthy Safe modules
test('TrustworthySafe01', normal, compile, [''])
test('TrustworthySafe02', normal, compile, [''])
test('TrustworthySafe03', normal, compile, [''])
test('TrustworthySafe04', normal, compile, [''])

# Check -fwarn-unsafe works
test('UnsafeWarn01', normal, compile, [''])
test('UnsafeWarn02', normal, compile, [''])
test('UnsafeWarn03', normal, compile, [''])
test('UnsafeWarn04', normal, compile, [''])
test('UnsafeWarn05', normal, compile, [''])
test('UnsafeWarn06', normal, compile, [''])
test('UnsafeWarn07', normal, compile, [''])

# Chck -fwa-safe works
test('SafeWarn01', normal, compile, [''])


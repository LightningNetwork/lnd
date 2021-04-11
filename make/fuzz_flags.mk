FUZZPKG = brontide lnwire tlv wtwire zpay32
FUZZ_TEST_RUN_TIME = 30
FUZZ_TEST_TIMEOUT = 20
FUZZ_NUM_PROCESSES = 4
FUZZ_BASE_WORKDIR = $(shell pwd)/fuzz

# If specific package is being fuzzed, construct the full name of the
# subpackage.
ifneq ($(pkg),)
FUZZPKG := $(pkg)
endif

# The default run time per fuzz test is pretty low and normally will be
# overwritten by a user depending on the time they have available.
ifneq ($(run_time),)
FUZZ_TEST_RUN_TIME := $(run_time)
endif

# If the timeout needs to be increased, overwrite the default value.
ifneq ($(timeout),)
FUZZ_TEST_TIMEOUT := $(timeout)
endif

# Overwrites the number of parallel processes. Should be set to the number of
# processor cores in a system.
ifneq ($(processes),)
FUZZ_NUM_PROCESSES := $(processes)
endif

# Overwrite the base work directory for the fuzz run. Can be used to supply any
# previously generated corpus.
ifneq ($(base_workdir),)
FUZZ_BASE_WORKDIR := $(base_workdir)
endif

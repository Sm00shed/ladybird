if (UNIX AND NOT APPLE)
    ladybird_test("TestNewfstatatEmulation.cpp" LibSandbox LIBS LibSandbox)
endif()

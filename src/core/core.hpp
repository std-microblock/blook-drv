#pragma once

// Core module - utilities for kernel mode without STL

#include "error.hpp"
#include "expected.hpp"
#include "pe.hpp"
#include "syscall.hpp"
#include "utils.hpp"

// Logging macro

#define log(format, ...)                                                  \
    DbgPrintEx(                                                           \
        DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                          \
        "[ BlookDrv ] [%s:%d %s] " format "\n",                           \
        strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__, \
        __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define ASSERT_TRUE_ERR(cond, error_code) ASSERT_EQ_ERR(!!(cond), true, error_code)

#define ASSERT_EQ_ERR(actual, expected, error_code)                \
    do {                                                           \
        auto _x_val = (actual);                                    \
        auto _y_val = (expected);                                  \
        if (_x_val != _y_val) {                                    \
            log("Assertion failed: %s (expected= %d, actual= %d)", \
                #actual " == " #expected, _y_val, _x_val);         \
            return core::err(core::ErrorCode::error_code);         \
        }                                                          \
    } while (0)

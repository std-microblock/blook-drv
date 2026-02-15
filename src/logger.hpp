#pragma once
#include <ntddk.h>

#define DBG_TAG "KMDF_DRV: "

#define LOG_FORMAT(fmt) DBG_TAG "[%s:%d] [%s] " fmt "\n"

#define LOG_ERR(fmt, ...)                                                \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, LOG_FORMAT(fmt), \
               __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...)                                               \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, LOG_FORMAT(fmt), \
               __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...)                                               \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, LOG_FORMAT(fmt), \
               __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#ifdef DBG
#define LOG_DBG(fmt, ...) LOG_INFO(fmt, ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)
#endif

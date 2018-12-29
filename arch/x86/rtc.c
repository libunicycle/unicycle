// SPDX-License-Identifier: MIT

#include "rtc.h"
#include "mem.h"
#include "x86.h"

#define REG_RTC_INDEX 0x70
#define REG_rtc_date 0x71

#define REG_SECONDS 0
#define REG_SECONDS_ALARM 1
#define REG_MINUTES 2
#define REG_MINUTES_ALARM 3
#define REG_HOURS 4
#define REG_HOURS_ALARM 5
#define REG_DAY_OF_WEEK 6
#define REG_DAY_OF_MONTH 7
#define REG_MONTH 8
#define REG_YEAR 9
#define REG_A 10
#define REG_B 11
#define REG_C 12
#define REG_D 13

// Register B bits
#define REG_B_HOUR_FORMAT BIT(1)
#define REG_B_DATA_MODE BIT(2)

// Register HOURS bits
#define REG_HOURS_PM BIT(7)

static uint8_t from_bcd(uint8_t data) { return (data >> 4) * 10 + (data & 0xf); }

static uint8_t rtc_reg_read_raw(uint8_t reg) {
    outb(REG_RTC_INDEX, reg);
    return inb(REG_rtc_date);
}

static uint8_t rtc_reg_read(uint8_t reg, bool is_binary) {
    uint8_t data = rtc_reg_read_raw(reg);
    return is_binary ? data : from_bcd(data);
}

static void rtc_read_mode(bool *is_24_hour, bool *is_binary) {
    uint8_t reg_b = rtc_reg_read_raw(REG_B);
    *is_24_hour = reg_b & REG_B_HOUR_FORMAT;
    *is_binary = reg_b & REG_B_DATA_MODE;
}

static uint8_t rtc_read_hour(bool is_binary, bool is_24_hour) {
    uint8_t data = rtc_reg_read_raw(REG_HOURS);

    bool pm = data & REG_HOURS_PM;
    data &= ~REG_HOURS_PM;

    uint8_t hour = is_binary ? data : from_bcd(data);

    if (is_24_hour) {
        return hour;
    }

    if (hour == 12) {
        hour = 0;
    }

    if (pm) {
        hour += 12;
    }

    return hour;
}

static void rtc_read_date(struct rtc_date *date) {
    bool is_24_hour, is_binary;
    rtc_read_mode(&is_24_hour, &is_binary);

    date->seconds = rtc_reg_read(REG_SECONDS, is_binary);
    date->minutes = rtc_reg_read(REG_MINUTES, is_binary);
    date->hours = rtc_read_hour(is_binary, is_24_hour);
    date->day = rtc_reg_read(REG_DAY_OF_MONTH, is_binary);
    date->month = rtc_reg_read(REG_MONTH, is_binary);
    date->year = rtc_reg_read(REG_YEAR, is_binary) + 2000;
}

void rtc_read(struct rtc_date *date) {
    struct rtc_date *prev;
    do {
        // keep reading date until two consecutive reads show the same data
        memcpy(&prev, date, sizeof(struct rtc_date));
        rtc_read_date(date);
    } while (memcmp(date, &prev, sizeof(struct rtc_date)));
}

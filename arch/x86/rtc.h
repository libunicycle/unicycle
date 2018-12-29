// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>

struct rtc_date {
    uint8_t seconds;
    uint8_t minutes;
    uint8_t hours;
    uint8_t day;
    uint8_t month;
    uint16_t year;
};

void rtc_read(struct rtc_date *data);

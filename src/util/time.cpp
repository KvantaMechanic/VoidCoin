// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/time.h>

#include <compat/compat.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<std::chrono::seconds> g_mock_time{}; //!< For testing
std::atomic<bool> g_used_system_time{false};
static std::atomic<std::chrono::milliseconds> g_mock_steady_time{}; //!< For testing

NodeClock::time_point NodeClock::now() noexcept
{
    const auto mocktime{g_mock_time.load(std::memory_order_relaxed)};
    if (!mocktime.count()) {
        g_used_system_time = true;
    }
    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::system_clock::now().time_since_epoch()};
    assert(ret > 0s);
    return time_point{ret};
};

void SetMockTime(int64_t nMockTimeIn) { SetMockTime(std::chrono::seconds{nMockTimeIn}); }
void SetMockTime(std::chrono::seconds mock_time_in)
{
    Assert(mock_time_in >= 0s);
    g_mock_time.store(mock_time_in, std::memory_order_relaxed);
}

std::chrono::seconds GetMockTime()
{
    return g_mock_time.load(std::memory_order_relaxed);
}

MockableSteadyClock::time_point MockableSteadyClock::now() noexcept
{
    const auto mocktime{g_mock_steady_time.load(std::memory_order_relaxed)};
    if (!mocktime.count()) {
        g_used_system_time = true;
    }
    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::steady_clock::now().time_since_epoch()};
    return time_point{ret};
};

void MockableSteadyClock::SetMockTime(std::chrono::milliseconds mock_time_in)
{
    Assert(mock_time_in >= 0s);
    g_mock_steady_time.store(mock_time_in, std::memory_order_relaxed);
}

void MockableSteadyClock::ClearMockTime()
{
    g_mock_steady_time.store(0ms, std::memory_order_relaxed);
}

int64_t GetTime() { return GetTime<std::chrono::seconds>().count(); }

std::string FormatISO8601DateTime(int64_t nTime)
{
    // C++17 compatible implementation using gmtime
    const time_t t{static_cast<time_t>(nTime)};
    struct tm tm_result{};
#ifdef _WIN32
    gmtime_s(&tm_result, &t);
    const auto& ymd_tm = tm_result;
#else
    gmtime_r(&t, &tm_result);
    const auto& ymd_tm = tm_result;
#endif
    // Create compatible accessors
    struct { int year() const { return t->tm_year + 1900; }
             unsigned month() const { return t->tm_mon + 1; }
             unsigned day() const { return t->tm_mday; }
             const struct tm* t;
    } ymd{&ymd_tm};
    struct { int hours() const { return t->tm_hour; }
             int minutes() const { return t->tm_min; }
             int seconds() const { return t->tm_sec; }
             const struct tm* t;
    } hms{&ymd_tm};
    return strprintf("%04i-%02u-%02uT%02i:%02i:%02iZ", signed{ymd.year()}, unsigned{ymd.month()}, unsigned{ymd.day()}, hms.hours(), hms.minutes(), hms.seconds());
}

std::string FormatISO8601Date(int64_t nTime)
{
    const time_t t{static_cast<time_t>(nTime)};
    struct tm tm_result{};
#ifdef _WIN32
    gmtime_s(&tm_result, &t);
#else
    gmtime_r(&t, &tm_result);
#endif
    return strprintf("%04i-%02u-%02u",
        tm_result.tm_year + 1900,
        (unsigned)(tm_result.tm_mon + 1),
        (unsigned)tm_result.tm_mday);
}

std::optional<int64_t> ParseISO8601DateTime(std::string_view str)
{
    constexpr auto FMT_SIZE{std::string_view{"2000-01-01T01:01:01Z"}.size()};
    if (str.size() != FMT_SIZE || str[4] != '-' || str[7] != '-' || str[10] != 'T' || str[13] != ':' || str[16] != ':' || str[19] != 'Z') {
        return {};
    }
    const auto year{ToIntegral<uint16_t>(str.substr(0, 4))};
    const auto month{ToIntegral<uint8_t>(str.substr(5, 2))};
    const auto day{ToIntegral<uint8_t>(str.substr(8, 2))};
    const auto hour{ToIntegral<uint8_t>(str.substr(11, 2))};
    const auto min{ToIntegral<uint8_t>(str.substr(14, 2))};
    const auto sec{ToIntegral<uint8_t>(str.substr(17, 2))};
    if (!year || !month || !day || !hour || !min || !sec) {
        return {};
    }
    // Use mktime for MinGW compatibility (year_month_day not available in MinGW C++20)
    struct tm t{};
    t.tm_year = *year - 1900;
    t.tm_mon  = *month - 1;
    t.tm_mday = *day;
    t.tm_hour = *hour;
    t.tm_min  = *min;
    t.tm_sec  = *sec;
    t.tm_isdst = 0;
#ifdef _WIN32
    time_t epoch = _mkgmtime(&t);
#else
    time_t epoch = timegm(&t);
#endif
    if (epoch == -1) return {};
    return int64_t{epoch};
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

struct timeval MillisToTimeval(std::chrono::milliseconds ms)
{
    return MillisToTimeval(count_milliseconds(ms));
}

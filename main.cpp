#include <format>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>

#include <fnmatch.h>

//#ifndef DEBUG
//#define DEBUG
//#endif

template<class Duration>
struct timer {
    explicit timer(const std::string_view &name, bool quiet = false)
        : m_start(std::chrono::high_resolution_clock::now()), m_name(name), m_quiet(quiet) {}

    ~timer() {
        if (not m_quiet) {
            std::cerr << m_name << ":" << count();
            if constexpr (std::is_same_v<Duration, std::chrono::nanoseconds>) {
                std::cerr << "ns";
            } else if constexpr (std::is_same_v<Duration, std::chrono::microseconds>) {
                std::cerr << "us";
            } else if constexpr (std::is_same_v<Duration, std::chrono::milliseconds>) {
                std::cerr << "ms";
            } else if constexpr (std::is_same_v<Duration, std::chrono::seconds>) {
                std::cerr << "s";
            } else {
                std::cerr << "unknown";
            }
            std::cerr << std::endl;
        }
    }

    template<class DurationType = Duration>
    [[nodiscard]]
    long long count() const {
        using namespace std::chrono;
        return duration_cast<DurationType>(high_resolution_clock::now() - m_start).count();
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_start;
    std::string_view m_name;
    bool m_quiet;
};

struct memdb_error : public std::exception {};

struct bad_type : public memdb_error {
    [[nodiscard]]
    const char *what() const noexcept override {
        return "bad type";
    }
};


class memdb {

    enum class type {
        scalar,
        hash,
        list,
        set,
        zset
    };


    using string_cref = std::reference_wrapper<const std::string>;
    using string_ref = std::reference_wrapper<std::string>;

    using hash_type = std::unordered_map<std::string, std::string>;

    using variants = std::variant<std::string, hash_type>;

    struct key_store_entry {
        type m_type;
        variants m_content;

        key_store_entry(type t, variants &&content) : m_type(t), m_content(std::move(content)) {}

        template<class T>
        [[nodiscard]]
        const T &get() const {
            if (auto *p = std::get_if<T>(&m_content)) {
                return *p;
            }
            throw bad_type{};
        }

        template<class T>
        T &get() {
            if (auto *p = std::get_if<T>(&m_content)) {
                return *p;
            }
            throw bad_type{};
        }
    };


public:
    bool set(std::string &&key, std::string &&content) {
        timer<std::chrono::nanoseconds> t("set");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            m_key_store.emplace(std::move(key), key_store_entry{type::scalar, std::move(content)});
            return true;
        }
        it->second = key_store_entry{type::scalar, std::move(content)};
        return false;
    }

    [[nodiscard]]
    std::optional<std::string_view> get(const std::string &key) const {
        timer<std::chrono::nanoseconds> t("get");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            return std::nullopt;
        }
        return it->second.get<std::string>();
    }

    bool del(const std::string &key) {
        timer<std::chrono::nanoseconds> t("del");
        return m_key_store.erase(key) > 0;
    }

    bool hset(std::string &&key, std::string &&field, std::string &&content) {
        timer<std::chrono::nanoseconds> t("hset");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end() || it->second.m_type != type::hash) {
            hash_type h;
            h.emplace(std::move(field), std::move(content));
            auto entry = key_store_entry{type::hash, std::move(h)};
            if (it == m_key_store.end()) {
                m_key_store.emplace(std::move(key), std::move(entry));
                return true;
            }
            it->second = std::move(entry);
            return false;
        }
        it->second.get<hash_type>().emplace(std::move(field), std::move(content));
        return true;
    }

    long long hmset(const std::string &key, const std::unordered_map<std::string, std::string> &fields) {
        timer<std::chrono::nanoseconds> t("hmset");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end() || it->second.m_type != type::hash) {
            auto entry = key_store_entry{type::hash, hash_type(fields)};
            if (it == m_key_store.end()) {
                m_key_store.emplace(key, std::move(entry));
                return static_cast<long long>(fields.size());
            }
            it->second = std::move(entry);
            return static_cast<long long>(fields.size());
        }
        auto &h = it->second.get<hash_type>();
        long long count = 0;
        for (const auto &[field, content]: fields) {
            if (auto hash_it = h.find(field); hash_it == h.end()) {
                h.emplace(field, content);
                ++count;
            } else {
                it->second.get<std::string>() = content;
            }
        }
        return count;
    }


    [[nodiscard]]
    std::optional<std::string_view> hget(const std::string &key, const std::string &field) const {
        timer<std::chrono::nanoseconds> t("hget");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            return std::nullopt;
        }
        if (it->second.m_type != type::hash) {
            throw bad_type{};
        }
        auto &h = it->second.get<hash_type>();
        auto it2 = h.find(field);
        if (it2 == h.end()) {
            return std::nullopt;
        }
        return it2->second;
    }

    [[nodiscard]]
    std::vector<std::string_view> hkeys(const std::string &key) const {
        timer<std::chrono::nanoseconds> t("hkeys");
        std::vector<std::string_view> result;
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            return result;
        }
        if (it->second.m_type != type::hash) {
            throw bad_type{};
        }
        const auto &h = it->second.get<hash_type>();
        result.reserve(h.size());
        for (const auto &[field, _]: h) {
            result.emplace_back(field);
        }
        return result;
    }

    [[nodiscard]]
    std::vector<std::optional<std::string_view>> hmget(const std::string &key, const std::vector<std::string> &fields) const {
        timer<std::chrono::nanoseconds> t("hmget");
        std::vector<std::optional<std::string_view>> result;
        result.reserve(fields.size());
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            result.resize(fields.size());
            return result;
        }
        if (it->second.m_type != type::hash) {
            throw bad_type{};
        }
        auto &h = it->second.get<hash_type>();
        for (const auto &field: fields) {
            auto it2 = h.find(field);
            if (it2 == h.end()) {
                result.emplace_back(std::nullopt);
            } else {
                result.emplace_back(it2->second);
            }
        }
        return result;
    }

    [[nodiscard]]
    std::vector<std::pair<std::string_view, std::string_view>> hgetall(const std::string &key) const {
        timer<std::chrono::nanoseconds> t("hgetall");
        std::vector<std::pair<std::string_view, std::string_view>> result;
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            return result;
        }
        if (it->second.m_type != type::hash) {
            throw bad_type{};
        }
        const auto &h = it->second.get<hash_type>();
        result.reserve(h.size());
        for (const auto &[field, content]: h) {
            result.emplace_back(field, content);
        }
        return result;
    }


    static bool glob_match(const std::string &value, const std::string &glob) {
        return fnmatch(glob.c_str(), value.c_str(), 0) == 0;
    }

    [[nodiscard]]
    std::vector<std::string_view> keys(const std::string &glob) const {
        timer<std::chrono::nanoseconds> t("keys");
        std::vector<std::string_view> result;
        result.reserve(m_key_store.size());

        for (const auto &[key, entry]: m_key_store) {
            if (glob.empty() || glob_match(key, glob)) {
                result.emplace_back(key);
            }
        }
        result.shrink_to_fit();
        return result;
    }

    // incr
    [[nodiscard]]
    long long incr(const std::string &key) {
        timer<std::chrono::nanoseconds> t("incr");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            m_key_store.emplace(key, key_store_entry{type::scalar, "1"});
            return 1;
        }
        auto &value = it->second.get<std::string>();
        try {
            long long next_value = std::stoll(value) + 1;
            it->second.get<std::string>() = std::move(std::to_string(next_value));
            return next_value;
        } catch (const std::exception &) {
            throw bad_type{};
        }
    }

    // decr
    [[nodiscard]]
    long long decr(const std::string &key) {
        timer<std::chrono::nanoseconds> t("decr");
        auto it = m_key_store.find(key);
        if (it == m_key_store.end()) {
            m_key_store.emplace(key, key_store_entry{type::scalar, "-1"});
            return -1;
        }
        auto &value = it->second.get<std::string>();
        try {
            long long next_value = std::stoll(value) - 1;
            it->second.get<std::string>() = std::move(std::to_string(next_value));
            return next_value;
        } catch (const std::exception &) {
            throw bad_type{};
        }
    }

private:
    std::unordered_map<std::string, key_store_entry> m_key_store;
};

void handle_set(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key, value;
    iss >> std::quoted(key) >> std::quoted(value);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'set' command";
        return;
    }
    os << (db.set(std::move(key), std::move(value)) ? "1" : "0");
}

void handle_get(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'get' command";
        return;
    }
    if (auto value = db.get(key)) {
        os << "\"" << *value << "\"";
    } else {
        os << "(nil)";
    }
}

void handle_del(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'del' command";
        return;
    }
    os << (db.del(key) ? "1" : "0");
}

void handle_hget(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key, field;
    iss >> std::quoted(key) >> std::quoted(field);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'hget' command";
        return;
    }
    if (auto value = db.hget(key, field)) {
        os << "\"" << *value << "\"";
    } else {
        os << "(nil)";
    }
}

void handle_hmget(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    std::vector<std::string> fields;
    auto to_string = [](std::optional<std::string_view> value) {
        std::stringstream ss;
        if (value) {
            ss << "\"" << *value << "\"";
        } else {
            ss << "(nil)";
        }
        return ss.str();
    };
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'hmget' command";
        return;
    }
    std::string field;
    while (iss >> std::quoted(field)) {
        fields.emplace_back(std::move(field));
    }
    if (fields.empty()) {
        os << "(error) ERR wrong number of arguments for 'hmget' command";
        return;
    }
    auto values = db.hmget(key, fields);
    if (values.empty()) {
        os << "(empty array)";
        return;
    }
    os << "1) " << to_string(values[0]);
    for (size_t i = 1; i < values.size(); ++i) {
        os << "\n"
           << i + 1 << ") " << to_string(values[i]);
    }
}


void handle_hset(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key, field, value;
    iss >> std::quoted(key) >> std::quoted(field) >> std::quoted(value);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'hset' command";
        return;
    }
    os << (db.hset(std::move(key), std::move(field), std::move(value)) ? "1" : "0");
}


void handle_hmset(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    std::unordered_map<std::string, std::string> fields;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'hmset' command";
        return;
    }
    std::string field, value;
    while (iss >> std::quoted(field) >> std::quoted(value)) {
        fields.emplace(std::move(field), std::move(value));
    }
    if (fields.empty()) {
        os << "(error) ERR wrong number of arguments for 'hmset' command";
        return;
    }
    os << db.hmset(key, fields);
}


void handle_keys(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string glob;
    iss >> std::quoted(glob);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'keys' command";
        return;
    }
    auto keys = db.keys(glob);
    if (keys.empty()) {
        os << "(empty array)";
        return;
    }
    os << "1) " << keys[0];
    for (size_t i = 1; i < keys.size(); ++i) {
        os << "\n"
           << i + 1 << ") " << keys[i];
    }
}

void handle_incr(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'incr' command";
        return;
    }
    os << db.incr(key);
}

void handle_decr(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'decr' command";
        return;
    }
    os << db.decr(key);
}

void handle_hkeys(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'hkeys' command";
        return;
    }
    auto keys = db.hkeys(key);
    if (keys.empty()) {
        os << "(empty array)";
        return;
    }
    os << "1) " << keys[0];
    for (size_t i = 1; i < keys.size(); ++i) {
        os << "\n"
           << i + 1 << ") " << keys[i];
    }
}

void handle_hgetall(memdb &db, std::ostream &os, std::istringstream &iss) {
    std::string key;
    iss >> std::quoted(key);
    if (iss.fail()) {
        os << "(error) ERR wrong number of arguments for 'hgetall' command";
        return;
    }
    auto values = db.hgetall(key);
    if (values.empty()) {
        os << "(empty array)";
        return;
    }
    os << "1) \"" << values[0].first << "\"\n"
       << "2) \"" << values[0].second << "\"";
    for (size_t i = 1; i < values.size(); ++i) {
        os << "\n"
           << 2 * i + 1 << ") \"" << values[i].first << "\"\n"
           << 2 * i + 2 << ") \"" << values[i].second << "\"";
    }
}

void process_input(memdb &db, const std::string &input, std::ostream &os) {
    using handler_type = std::function<void(memdb & db, std::ostream & os, std::istringstream &)>;
    static std::unordered_map<std::string, handler_type> commands{
            {"set", handle_set},
            {"get", handle_get},
            {"del", handle_del},
            {"hget", handle_hget},
            {"hmget", handle_hmget},
            {"hset", handle_hset},
            {"hkeys", handle_hkeys},
            {"hgetall", handle_hgetall},
            {"hmset", handle_hmset},
            {"keys", handle_keys},
            {"incr", handle_incr},
            {"decr", handle_decr},
    };

    std::string command;
    std::istringstream iss(input);
    iss >> std::quoted(command);
    if (command == "help") {
        os << "Commands:\n";
        for (const auto &cmd: commands) {
            os << cmd.first << "\n";
        }
        return;
    }
    std::transform(command.begin(), command.end(), command.begin(), [](unsigned char c) { return std::tolower(c); });
    if (auto it = commands.find(command); it != commands.end()) {
        try {
            it->second(db, os, iss);
        } catch (const std::exception &e) {
            os << "(error) ERR " << e.what();
        }
    } else {
        os << "(error) ERR Unknown command";
    }
}


int main() {
    std::string line;
    memdb db;

    std::cout << "memdb> ";
    while (std::getline(std::cin, line)) {
        if (line.starts_with("quit") or line.starts_with("exit")) {
            break;
        }
        if (not line.empty()) {
            process_input(db, line, std::cout);
            std::cout << std::endl;
        }
        std::cout << "memdb> ";
    }


    return 0;
}

#include <algorithm>
#include <array>
#include <cstddef>
#include <iostream>
#include <unordered_map>
#include <vector>

constexpr int P = 251;
using State = std::array<int, 8>;
using Row = std::array<int, 9>;
using Matrix = std::array<Row, 8>;
using Journal = std::vector<int>;

struct Limb {
    std::array<int, 7> a, b, c, d;
};

template <class Step>
void each_step(const Limb& limb, Step step) {
    for (int i = 0; i < 7; ++i)
        step(i + 1, i, limb.a[i], limb.b[i]);
    for (int i = 6; i >= 0; --i)
        step(i, i + 1, limb.c[i], limb.d[i]);
}

int mod(int x) {
    return (x % P + P) % P;
}

// Compose an observed output row on the right with the inverse turn.
void undo_on_row(Row& row, const Limb& limb) {
    each_step(limb, [&](int dst, int src, int scale, int offset) {
        row[src] = mod(row[src] - scale * row[dst]);
        row[8] = mod(row[8] - offset * row[dst]);
    });
}

template <class Value, class Turn, class Match>
void enumerate(const std::vector<Limb>& table, Journal& journal, int pos,
               const Value& value, const Turn& turn, const Match& match) {
    if (pos == static_cast<int>(journal.size())) {
        match(journal, value);
        return;
    }

    for (int i = 0; i < static_cast<int>(table.size()); ++i) {
        journal[pos] = i;
        Value next = value;
        turn(next, table[i]);
        enumerate(table, journal, pos + 1, next, turn, match);
    }
}

struct RowHash {
    std::size_t operator()(const Row& row) const {
        std::size_t hash = 2166136261u;
        for (int value : row)
            hash = (hash ^ static_cast<unsigned>(value)) * 16777619u;
        return hash;
    }
};

struct Candidate {
    Journal journal;
    Matrix target;
};

void search(int order, int depth, int seal, const State& start, const Matrix& observed,
            const std::vector<Limb>& first, const std::vector<Limb>& second) {
    std::unordered_multimap<Row, Candidate, RowHash> candidates;
    Journal journal(depth);
    enumerate(first, journal, 0, start, [](State& state, const Limb& limb) {
        each_step(limb, [&](int dst, int src, int scale, int offset) {
            state[dst] = (state[dst] + scale * state[src] + offset) % P;
        });
    }, [&](const Journal& code, const State& state) {
        int sum = 0;
        for (int value : state)
            sum += value;
        if (sum % P != seal)
            return;

        Matrix target = observed;
        for (int index : code)
            for (Row& row : target)
                undo_on_row(row, first[index]);
        candidates.emplace(target[0], Candidate{code, target});
    });

    Matrix identity{};
    for (int i = 0; i < 8; ++i)
        identity[i][i] = 1;

    enumerate(second, journal, 0, identity, [](Matrix& matrix, const Limb& limb) {
        each_step(limb, [&](int dst, int src, int scale, int offset) {
            for (int j = 0; j < 9; ++j)
                matrix[dst][j] = (matrix[dst][j] + scale * matrix[src][j]) % P;
            matrix[dst][8] = (matrix[dst][8] + offset) % P;
        });
    }, [&](const Journal& code, const Matrix& matrix) {
        for (const Row& row : matrix) {
            const auto range = candidates.equal_range(row);
            for (auto it = range.first; it != range.second; ++it) {
                const Candidate& candidate = it->second;
                State wiring{};
                std::transform(candidate.target.begin(), candidate.target.end(), wiring.begin(),
                               [&](const Row& value) {
                    return std::find(matrix.begin(), matrix.end(), value) - matrix.begin();
                });
                if (std::find(wiring.begin(), wiring.end(), 8) != wiring.end())
                    continue;

                std::cout << order;
                for (int index : candidate.journal)
                    std::cout << ' ' << index;
                for (int index : code)
                    std::cout << ' ' << index;
                for (int channel : wiring)
                    std::cout << ' ' << channel;
                std::cout << '\n';
            }
        }
    });
}

int main() {
    int depth, night_count, morning_count, seal;
    std::cin >> depth >> night_count >> morning_count >> seal;
    std::vector<Limb> night(night_count), morning(morning_count);
    for (auto* table : {&night, &morning})
        for (auto& limb : *table)
            for (auto* values : {&limb.a, &limb.b, &limb.c, &limb.d})
                for (int& value : *values)
                    std::cin >> value;

    State start{};
    for (int& value : start)
        std::cin >> value;
    Matrix observed{};
    for (Row& row : observed)
        for (int& value : row)
            std::cin >> value;
    if (!std::cin)
        return 1;

    search(0, depth, seal, start, observed, night, morning);
    search(1, depth, seal, start, observed, morning, night);
}

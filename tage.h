#ifndef BRANCH_TAGE_H
#define BRANCH_TAGE_H

#include <array>
#include <bitset>
#include <vector>
#include <cmath>
#include "modules.h"
#include "msl/fwcounter.h"

struct tage : champsim::modules::branch_predictor {
  // Core TAGE parameters tuned for perlbench
  static constexpr std::size_t NUM_TAGGED_TABLES = 6;
  static constexpr std::size_t BASE_BITS = 14;          // 16K entry base table
  static constexpr std::size_t TABLE_BITS = 10;         // 1K entries per tagged table
  static constexpr std::size_t TAG_BITS = 13;           // 13-bit tags
  static constexpr std::size_t MAX_HISTORY_LENGTH = 200;
  
  // Derived constants
  static constexpr std::size_t BASE_TABLE_SIZE = 1 << BASE_BITS;
  static constexpr std::size_t TAGGED_TABLE_SIZE = 1 << TABLE_BITS;
  
  // Counter widths
  static constexpr std::size_t COUNTER_BITS_BASE = 2;
  static constexpr std::size_t COUNTER_BITS_TAGGED = 3;
  static constexpr std::size_t USEFUL_BITS = 2;
  
  // Table entry structure
  struct tag_entry {
    champsim::msl::fwcounter<COUNTER_BITS_TAGGED> pred_counter{};
    champsim::msl::fwcounter<USEFUL_BITS> useful_counter{};
    uint64_t tag = 0;
  };
  
  // Tables 
  std::array<champsim::msl::fwcounter<COUNTER_BITS_BASE>, BASE_TABLE_SIZE> base_table{};
  std::vector<std::vector<tag_entry>> tagged_tables;
  
  // Global history register
  std::bitset<MAX_HISTORY_LENGTH> global_history{};
  
  // History lengths for each tagged table
  std::array<std::size_t, NUM_TAGGED_TABLES> history_lengths{};
  
  // Prediction state tracking
  bool used_tagged_table = false;
  bool has_found_lmb = false;
  std::size_t base_index = 0;
  std::size_t tag_table_pos = 0;
  std::size_t longest_matching_branch = 0;
  std::size_t longest_index = 0;
  
  // Constructor
  using branch_predictor::branch_predictor;
  
  void init() {
    // Carefully tuned history lengths for perlbench
    history_lengths[0] = 12;
    history_lengths[1] = 27;
    history_lengths[2] = 44;
    history_lengths[3] = 63;
    history_lengths[4] = 101;
    history_lengths[5] = 160;
    
    // Initialize tagged tables
    tagged_tables.resize(NUM_TAGGED_TABLES);
    for (std::size_t i = 0; i < NUM_TAGGED_TABLES; i++) {
      tagged_tables[i].resize(TAGGED_TABLE_SIZE);
    }
    
    // Initialize base table to weak taken state
    for (auto& entry : base_table) {
      entry += 1;  // Start at weak taken (value=1)
    }
  }
  
  // Helper functions for indexing and tag generation
  std::size_t get_base_index(champsim::address ip);
  std::size_t get_tag_index(champsim::address ip, std::size_t table_idx);
  uint64_t get_partial_tag(champsim::address ip, std::size_t table_idx);
  uint64_t get_compressed_history(std::size_t history_length, std::size_t width);
  
  // ChampSim interface
  bool predict_branch(champsim::address ip);
  void last_branch_result(champsim::address ip, champsim::address branch_target, bool taken, uint8_t branch_type);
};

#endif // BRANCH_TAGE_H
#include "tage.h"

// Get index for base table (T0)
std::size_t tage::get_base_index(champsim::address ip)
{
  return (ip.to<uint64_t>() >> 2) & (BASE_TABLE_SIZE - 1);
}

// Get index for tagged tables using compressed history
std::size_t tage::get_tag_index(champsim::address ip, std::size_t table_idx)
{
  std::size_t length = history_lengths[table_idx];
  uint64_t compressed_hist = get_compressed_history(length, TABLE_BITS);
  std::size_t pc_part = (ip.to<uint64_t>() >> 2) & ((1ULL << TABLE_BITS) - 1);
  
  return (pc_part ^ compressed_hist) & (TAGGED_TABLE_SIZE - 1);
}

// Get partial tag for tagged tables
uint64_t tage::get_partial_tag(champsim::address ip, std::size_t table_idx)
{
  uint64_t pc_part = (ip.to<uint64_t>() >> (2 + TABLE_BITS)) & ((1ULL << TAG_BITS) - 1);
  std::size_t length = history_lengths[table_idx];
  uint64_t hist_part = 0;
  
  for (std::size_t i = 0; i < TAG_BITS && i < length; i++) {
    if (global_history[i]) {
      hist_part ^= (1ULL << i);
    }
  }
  
  return (pc_part ^ hist_part) & ((1ULL << TAG_BITS) - 1);
}

// Calculate compressed history using folding
uint64_t tage::get_compressed_history(std::size_t history_length, std::size_t width)
{
  if (history_length <= width)
    return 0;
    
  uint64_t compressed = 0;
  std::size_t pieces = (history_length + width - 1) / width;
  
  for (std::size_t p = 0; p < pieces; p++) {
    uint64_t piece = 0;
    for (std::size_t i = 0; i < width && (p * width + i) < history_length; i++) {
      if ((p * width + i) < MAX_HISTORY_LENGTH && global_history[p * width + i]) {
        piece |= (1ULL << i);
      }
    }
    compressed ^= piece;
  }
  
  return compressed & ((1ULL << width) - 1);
}

// ===== Misprediction Pattern Cache (MPC) Implementation =====

// Get MPC index using branch PC
std::size_t tage::get_mpc_index(champsim::address ip)
{
  // Simple hash of PC for indexing
  uint64_t addr = ip.to<uint64_t>();
  uint32_t hash = (addr >> 2) ^ (addr >> 14) ^ (addr >> 25);
  return hash & (MPC_SIZE - 1);
}

// Check if MPC should override TAGE prediction
bool tage::check_mpc_override(champsim::address ip, bool tage_pred)
{
  auto& entry = mpc_table[mpc_index];
  uint64_t pc_tag = ip.to<uint64_t>();
  
  // Check if we have an entry for this branch
  if (entry.tag == pc_tag) {
    mpc_hit = true;
    
    // Only override if this branch frequently mispredicts
    if (entry.miss_count.value() >= 10 && entry.pattern_confidence.value() >= 5) {
      // Look for simple patterns in recent history
      // Count transitions in the pattern
      int transitions = 0;
      for (int i = 1; i < PATTERN_LEN; i++) {
        if (entry.recent_pattern[i] != entry.recent_pattern[i-1]) {
          transitions++;
        }
      }
      
      // If pattern shows alternating behavior, predict opposite of last
      if (transitions >= 5) {
        used_mpc = true;
        return !entry.last_pred;
      }
      
      // If pattern shows bias, use majority vote
      int taken_count = entry.recent_pattern.count();
      if (taken_count >= 6 || taken_count <= 2) {
        used_mpc = true;
        return taken_count >= 4;
      }
    }
  }
  
  return tage_pred;  // Use TAGE prediction
}

// Update MPC with branch outcome
void tage::update_mpc(champsim::address ip, bool taken, bool was_correct)
{
  auto& entry = mpc_table[mpc_index];
  uint64_t pc_tag = ip.to<uint64_t>();
  
  if (entry.tag == pc_tag) {
    // Update pattern history
    entry.recent_pattern <<= 1;
    entry.recent_pattern[0] = taken;
    
    // Update misprediction counter
    if (!was_correct) {
      entry.miss_count += 2;  // Increase on misprediction
    } else if (entry.miss_count.value() > 0) {
      entry.miss_count -= 1;  // Slowly decay on correct prediction
    }
    
    // Update pattern confidence
    // Check if current outcome matches expected pattern
    int taken_count = 0;
    for (int i = 1; i < PATTERN_LEN; i++) {
      if (entry.recent_pattern[i]) taken_count++;
    }
    bool expected = taken_count >= 4;
    
    if ((taken && expected) || (!taken && !expected)) {
      entry.pattern_confidence += 1;
    } else {
      entry.pattern_confidence -= 1;
    }
    
    entry.last_pred = taken;
  } else if (!was_correct) {
    // Allocate new entry on misprediction
    entry.tag = pc_tag;
    entry.recent_pattern.reset();
    entry.recent_pattern[0] = taken;
    entry.miss_count = champsim::msl::fwcounter<4>{2};
    entry.pattern_confidence = champsim::msl::fwcounter<3>{0};
    entry.last_pred = taken;
  }
}

// Make a branch prediction
bool tage::predict_branch(champsim::address ip)
{
  // Initialize predictor on first call
  static bool initialized = false;
  if (!initialized) {
    init();
    initialized = true;
  }

  // Reset prediction state
  used_tagged_table = false;
  has_found_lmb = false;
  mpc_hit = false;
  used_mpc = false;
  
  // Get base table prediction
  base_index = get_base_index(ip);
  bool prediction = base_table[base_index].value() >= (base_table[base_index].maximum / 2);
  
  // Check tagged tables from longest to shortest history
  for (int i = NUM_TAGGED_TABLES - 1; i >= 0; i--) {
    std::size_t tag_index = get_tag_index(ip, i);
    uint64_t partial_tag = get_partial_tag(ip, i);
    
    if (tagged_tables[i][tag_index].tag == partial_tag) {
      if (!has_found_lmb) {
        longest_matching_branch = i;
        tag_table_pos = i;
        longest_index = tag_index;
        has_found_lmb = true;
      }
      
      auto& entry = tagged_tables[i][tag_index];
      if (!(entry.pred_counter.value() == entry.pred_counter.maximum / 2 && 
            entry.useful_counter.value() == 0)) {
        prediction = entry.pred_counter.value() >= (entry.pred_counter.maximum / 2);
        used_tagged_table = true;
        break;
      }
    }
  }
  
  // Check MPC for problematic branches
  mpc_index = get_mpc_index(ip);
  prediction = check_mpc_override(ip, prediction);
  
  return prediction;
}

// Update predictor after resolving a branch
void tage::last_branch_result(champsim::address ip, champsim::address branch_target, bool taken, uint8_t branch_type)
{
  bool was_correct = false;
  
  // Update TAGE tables
  if (has_found_lmb) {
    auto& entry = tagged_tables[tag_table_pos][longest_index];
    bool tage_pred = entry.pred_counter.value() >= (entry.pred_counter.maximum / 2);
    was_correct = (used_mpc ? (taken == check_mpc_override(ip, tage_pred)) : (tage_pred == taken));
    
    // Only update TAGE if we didn't use MPC override
    if (!used_mpc) {
      entry.useful_counter += (tage_pred == taken) ? 1 : -1;
    }
    entry.pred_counter += taken ? 1 : -1;
  } else {
    bool base_pred = base_table[base_index].value() >= (base_table[base_index].maximum / 2);
    was_correct = (used_mpc ? (taken == check_mpc_override(ip, base_pred)) : (base_pred == taken));
    base_table[base_index] += taken ? 1 : -1;
  }
  
  // Update MPC
  update_mpc(ip, taken, was_correct);
  
  // Handle TAGE allocation on misprediction
  if (!was_correct && !used_mpc) {
    std::size_t start_table = used_tagged_table ? tag_table_pos + 1 : 0;
    bool allocated = false;
    
    for (std::size_t i = start_table; i < NUM_TAGGED_TABLES; i++) {
      std::size_t tag_index = get_tag_index(ip, i);
      uint64_t partial_tag = get_partial_tag(ip, i);
      
      if (tagged_tables[i][tag_index].useful_counter.value() == 0) {
        tagged_tables[i][tag_index].tag = partial_tag;
        tagged_tables[i][tag_index].pred_counter = champsim::msl::fwcounter<COUNTER_BITS_TAGGED>{
            taken ? (tagged_tables[i][tag_index].pred_counter.maximum / 2 + 1) :
                   (tagged_tables[i][tag_index].pred_counter.maximum / 2 - 1)};
        allocated = true;
        break;
      }
    }
    
    if (!allocated) {
      for (std::size_t i = start_table; i < NUM_TAGGED_TABLES; i++) {
        std::size_t tag_index = get_tag_index(ip, i);
        tagged_tables[i][tag_index].useful_counter -= 1;
      }
    }
  }
  
  // Update global history
  global_history <<= 1;
  global_history[0] = taken;
}
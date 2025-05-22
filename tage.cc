#include "tage.h"

// Get index for base table (T0)
std::size_t tage::get_base_index(champsim::address ip)
{
  // Simple direct-mapped indexing for the base table
  return (ip.to<uint64_t>() >> 2) & (BASE_TABLE_SIZE - 1);
}

// Get index for tagged tables using compressed history
std::size_t tage::get_tag_index(champsim::address ip, std::size_t table_idx)
{
  // Get the history length for this table
  std::size_t length = history_lengths[table_idx];
  
  // Compress the history to the table index width
  uint64_t compressed_hist = get_compressed_history(length, TABLE_BITS);
  
  // Extract PC bits for the index
  std::size_t pc_part = (ip.to<uint64_t>() >> 2) & ((1ULL << TABLE_BITS) - 1);
  
  // XOR PC bits with compressed history for better distribution
  return (pc_part ^ compressed_hist) & (TAGGED_TABLE_SIZE - 1);
}

// Get partial tag for tagged tables
uint64_t tage::get_partial_tag(champsim::address ip, std::size_t table_idx)
{
  // Different PC bits for tag to avoid correlation with index
  uint64_t pc_part = (ip.to<uint64_t>() >> (2 + TABLE_BITS)) & ((1ULL << TAG_BITS) - 1);
  
  // Use a different folding for the tag to avoid correlation with index
  std::size_t length = history_lengths[table_idx];
  uint64_t hist_part = 0;
  
  for (std::size_t i = 0; i < TAG_BITS && i < length; i++) {
    if (global_history[i]) {
      hist_part ^= (1ULL << i);
    }
  }
  
  // XOR PC bits with history bits for final tag
  return (pc_part ^ hist_part) & ((1ULL << TAG_BITS) - 1);
}

// Calculate compressed history using folding
uint64_t tage::get_compressed_history(std::size_t history_length, std::size_t width)
{
  // Short histories don't need folding
  if (history_length <= width)
    return 0;
    
  uint64_t compressed = 0;
  std::size_t pieces = (history_length + width - 1) / width;
  
  // Fold history into pieces and XOR them together
  for (std::size_t p = 0; p < pieces; p++) {
    uint64_t piece = 0;
    for (std::size_t i = 0; i < width && (p * width + i) < history_length; i++) {
      if ((p * width + i) < MAX_HISTORY_LENGTH && global_history[p * width + i]) {
        piece |= (1ULL << i);
      }
    }
    // XOR this piece into the result
    compressed ^= piece;
  }
  
  return compressed & ((1ULL << width) - 1);
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
  
  // Get base table prediction
  base_index = get_base_index(ip);
  bool prediction = base_table[base_index].value() >= (base_table[base_index].maximum / 2);
  
  // Check tagged tables from longest to shortest history
  for (int i = NUM_TAGGED_TABLES - 1; i >= 0; i--) {
    std::size_t tag_index = get_tag_index(ip, i);
    uint64_t partial_tag = get_partial_tag(ip, i);
    
    if (tagged_tables[i][tag_index].tag == partial_tag) {
      if (!has_found_lmb) {
        // Remember the longest matching branch for updating
        longest_matching_branch = i;
        tag_table_pos = i;
        longest_index = tag_index;
        has_found_lmb = true;
      }
      
      // Only use prediction if useful counter is not 0 or pred is not weak
      auto& entry = tagged_tables[i][tag_index];
      if (!(entry.pred_counter.value() == entry.pred_counter.maximum / 2 && 
            entry.useful_counter.value() == 0)) {
        prediction = entry.pred_counter.value() >= (entry.pred_counter.maximum / 2);
        used_tagged_table = true;
        break;
      }
    }
  }
  
  return prediction;
}

// Update predictor after resolving a branch
void tage::last_branch_result(champsim::address ip, champsim::address branch_target, bool taken, uint8_t branch_type)
{
  // Determine if prediction was correct based on provider component
  if (has_found_lmb) {
    // Update the provider entry
    auto& entry = tagged_tables[tag_table_pos][longest_index];
    
    // Update useful counter if prediction was correct
    bool was_correct = (entry.pred_counter.value() >= (entry.pred_counter.maximum / 2)) == taken;
    entry.useful_counter += was_correct ? 1 : -1;
    
    // Update prediction counter
    entry.pred_counter += taken ? 1 : -1;
    
    // If prediction was correct, just update history and return
    if (was_correct) {
      // Update global history
      global_history <<= 1;
      global_history[0] = taken;
      return;
    }
  } else {
    // Update base table if it was the provider
    base_table[base_index] += taken ? 1 : -1;
    
    // If prediction was correct, just update history and return
    if ((base_table[base_index].value() >= (base_table[base_index].maximum / 2)) == taken) {
      // Update global history
      global_history <<= 1;
      global_history[0] = taken;
      return;
    }
  }
  
  // If we reach here, prediction was wrong, try to allocate new entry
  
  // Start allocating from the table after the one that provided prediction
  std::size_t start_table = used_tagged_table ? tag_table_pos + 1 : 0;
  bool allocated = false;
  
  // Try to find a table with useful counter = 0
  for (std::size_t i = start_table; i < NUM_TAGGED_TABLES; i++) {
    std::size_t tag_index = get_tag_index(ip, i);
    uint64_t partial_tag = get_partial_tag(ip, i);
    
    if (tagged_tables[i][tag_index].useful_counter.value() == 0) {
      // Allocate new entry
      tagged_tables[i][tag_index].tag = partial_tag;
      
      // Initialize prediction counter based on taken
      if (taken)
        tagged_tables[i][tag_index].pred_counter = champsim::msl::fwcounter<COUNTER_BITS_TAGGED>{
            tagged_tables[i][tag_index].pred_counter.maximum / 2 + 1};
      else
        tagged_tables[i][tag_index].pred_counter = champsim::msl::fwcounter<COUNTER_BITS_TAGGED>{
            tagged_tables[i][tag_index].pred_counter.maximum / 2 - 1};
      
      allocated = true;
      break;
    }
  }
  
  // If no entry was allocated, decrease useful counters
  if (!allocated) {
    for (std::size_t i = start_table; i < NUM_TAGGED_TABLES; i++) {
      std::size_t tag_index = get_tag_index(ip, i);
      tagged_tables[i][tag_index].useful_counter -= 1;
    }
  }
  
  // Update global history
  global_history <<= 1;
  global_history[0] = taken;
}


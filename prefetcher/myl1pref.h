#ifndef HYBRID_L1D_PREFETCHER
#define HYBRID_L1D_PREFETCHER

#include "cache.h"
#include "modules.h"

#include <vector>
#include <cstdint>
#include <deque>


// The queues we use to check hits
constexpr unsigned MAX_PQ_SIZE = 8;
constexpr unsigned LOG2_CACHE_LINE_SIZE = 6;

// Delta history tracker
constexpr unsigned DHT_AHT_INDEX_BITS = 9;
constexpr unsigned DHT_AHT_NUM_ENTRIES = 1 << DHT_AHT_INDEX_BITS;
constexpr unsigned DHT_AHT_TAG_INITIAL_SHIFT = DHT_AHT_INDEX_BITS;
constexpr unsigned DHT_AHT_DELTA_HISTORY_SIZE = 3;
constexpr unsigned DHT_PHT_INDEX_BITS = 11;
constexpr unsigned DHT_PHT_NUM_ENTRIES = 1 << DHT_PHT_INDEX_BITS;
constexpr unsigned DHT_PHT_CONFIDENCE_MAX = 3;

// Region prefetcher
constexpr unsigned RP_LINES_PER_REGION_LOG2 = 3;
constexpr unsigned RP_LINES_PER_REGION = 1 << RP_LINES_PER_REGION_LOG2;
constexpr unsigned RP_REGION_MASK = RP_LINES_PER_REGION - 1;
constexpr unsigned RP_INDEX_BITS = 9;
constexpr unsigned RP_NUM_SETS = 1 << RP_INDEX_BITS;
constexpr unsigned RP_NUM_WAYS = 2;
constexpr unsigned RP_ACCESS_DENSITY_THRESHOLD = 3;

enum PrefetchSourceEngine {
  NONE = 0, 
  NL  = 1,
  DHT = 2,
  RP = 3
};

enum PrefetcherPhase {
  PHASE_EXPLORE,
  PHASE_EXPLOIT
};


//
struct DHT_AHT_entry_t {
  uint16_t tag : 16;
  uint64_t last_accessed_block : 48;
  std::array<int16_t, DHT_AHT_DELTA_HISTORY_SIZE> delta_history;
  bool valid : 1;

  DHT_AHT_entry_t() :
    tag(0),
    last_accessed_block(0),
    valid(false) {
    delta_history.fill(0);
  }

  void record_new_delta(int16_t nd) {
    for (int i = DHT_AHT_DELTA_HISTORY_SIZE - 1; i > 0; i--)
      delta_history[i] = delta_history[i-1];
    delta_history[0] = nd;
  }
  void reset() {
    last_accessed_block = 0;
    tag = 0;
    valid = false;
    delta_history.fill(0);
  }
};

struct DHT_PHT_entry_t {
  std::array<int16_t, DHT_AHT_DELTA_HISTORY_SIZE> tag_delta_history; // Same size of delta history as AHT
  int16_t predicted_next_delta : 10;
  uint8_t confidence : 2;
  bool valid : 1;

  DHT_PHT_entry_t() :
    predicted_next_delta(0),
    confidence(0),
    valid(false) {
    tag_delta_history.fill(0);
  }
  void reset() {
    predicted_next_delta = 0;
    confidence = 0;
    valid = false;
    tag_delta_history.fill(0);
  }
};

struct RP_entry_t {
  uint64_t region_address_tag : 40;
  uint8_t access_bitmap : 8;
  uint8_t prefetch_bitmap : 8;
  bool valid : 1;

  RP_entry_t() :
    region_address_tag(0),
    access_bitmap(0),
    prefetch_bitmap(0),
    valid(false) {}
  void reset() {
    region_address_tag = 0;
    access_bitmap = 0;
    prefetch_bitmap = 0;
    valid = false;
  }
};

class myl1pref : public champsim::modules::prefetcher {
private:
  std::vector<DHT_AHT_entry_t> AHT_table;
  std::vector<DHT_PHT_entry_t> PHT_table;
  std::vector<std::vector<RP_entry_t>> RP_table;
  std::vector<bool> src_lru_way;

  PrefetcherPhase current_phase; // bit to track which stage are we on
  uint64_t phase_cycle_counter;
  uint64_t explore_duration_cycles;
  uint64_t exploit_duration_cycles;

  bool allowed_nl;
  bool allowed_tdc;
  bool allowed_src;


  std::deque<uint64_t> recent_prefetches_nl;
  std::deque<uint64_t> recent_prefetches_tdc;
  std::deque<uint64_t> recent_prefetches_src;
  static const size_t MAX_RECENT_PF_TRACKING = 16; 

  int score_nl;
  int score_tdc;
  int score_src;

  static const int SCORE_MAX_PQ_HIT = 2048; 
  static const int SCORE_THRESHOLD_PREFETCHER = 1024;

  static const int PQ_HIT_REWARD_NL  = 1;
  static const int PQ_HIT_REWARD_DHT = 1;
  static const int PQ_HIT_REWARD_RP = 1;

  uint32_t get_aht_index(uint64_t pc) const;
  uint16_t get_aht_tag(uint64_t pc) const;
  uint32_t get_pht_index(const std::array<int16_t, DHT_AHT_DELTA_HISTORY_SIZE>& delta_hist) const;
  uint64_t get_src_region_address(uint64_t block_addr) const;
  uint8_t get_src_offset_in_region(uint64_t block_addr) const;
  uint32_t get_src_set_index(uint64_t region_addr) const;
  uint64_t get_src_tag(uint64_t region_addr) const;
  uint8_t find_src_victim(uint32_t set_idx) const;
  void update_src_lru(uint32_t set_idx, bool accessed_way);

  void manage_phase_transitions();
  void determine_best_engine_for_exploit();
  void reset_scores_and_pq_tracking(); 
  void track_issued_prefetch(PrefetchSourceEngine engine_id, uint64_t block_address);
  void check_pq_hits(uint64_t demand_block_address);
  bool issue_prefetch_wrapper(uint64_t prefetch_address, PrefetchSourceEngine engine_id);

  uint64_t num_prefetches_issued_nl;
  uint64_t num_prefetches_useful_nl;
  uint64_t num_prefetches_issued_tdc;
  uint64_t num_prefetches_useful_tdc;
  uint64_t num_prefetches_issued_src;
  uint64_t num_prefetches_useful_src;
  uint64_t num_prefetches_useful_total_champsim; 
  uint64_t pq_hits_nl_total;
  uint64_t pq_hits_tdc_total;
  uint64_t pq_hits_src_total;

  unsigned nl_prefetch_degree;

public:
  using champsim::modules::prefetcher::prefetcher;

  void prefetcher_initialize();
  void prefetcher_cycle_operate();
  void prefetcher_final_stats();
  uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address ip, bool cache_hit, bool useful_prefetch, access_type type, uint32_t metadata_in);
  uint32_t prefetcher_cache_fill(champsim::address addr, uint32_t set, uint32_t way, bool prefetch, champsim::address evicted_address, uint32_t metadata_in);
};

#endif

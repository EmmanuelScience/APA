#include "myl1pref.h"
#include <cstdint>
#include <string>
#include <algorithm>
#include <iostream>
#include <iomanip>

void myl1pref::prefetcher_initialize() {

    AHT_table.resize(DHT_AHT_NUM_ENTRIES);
    PHT_table.resize(DHT_PHT_NUM_ENTRIES);
    RP_table.resize(RP_NUM_SETS);
    for (auto& set : RP_table) {
        set.resize(RP_NUM_WAYS);
    }
    src_lru_way.resize(RP_NUM_SETS, 0);

    for (auto& entry : AHT_table) entry.reset();
    for (auto& entry : PHT_table) entry.reset();
    for (auto& set : RP_table) {
        for (auto& entry : set) entry.reset();
    }

    num_prefetches_issued_nl = 0;
    num_prefetches_useful_nl = 0; 
    num_prefetches_issued_tdc = 0;
    num_prefetches_useful_tdc = 0;
    num_prefetches_issued_src = 0;
    num_prefetches_useful_src = 0;
    num_prefetches_useful_total_champsim = 0;
    pq_hits_nl_total = 0;
    pq_hits_tdc_total = 0;
    pq_hits_src_total = 0;


    current_phase = PrefetcherPhase::PHASE_EXPLORE;
    phase_cycle_counter = 0;
    explore_duration_cycles = 256000; 
    exploit_duration_cycles = 256000 * 3; 
    allowed_tdc = false;
    allowed_src = false;
    allowed_nl = false;

    reset_scores_and_pq_tracking(); 

    nl_prefetch_degree = 1;

    printf("  AHT Table Entries: %u\n", DHT_AHT_NUM_ENTRIES);
    printf("  PHT Table Entries: %u\n", DHT_PHT_NUM_ENTRIES);
    printf("  RP Table Sets: %u, Ways: %u, Total Entries: %u\n", RP_NUM_SETS, RP_NUM_WAYS, RP_NUM_SETS * RP_NUM_WAYS);
    printf("  NL Prefetch Degree: %u\n", nl_prefetch_degree);
    printf("  EXPLORE Phase Duration: %lu cycles\n", explore_duration_cycles);
    printf("  EXPLOIT Phase Duration: %lu cycles\n", exploit_duration_cycles);
    printf("  Score System: PQ Hit Based, Positive Feedback Only.\n");
    printf("  NL Reward: %d, DHT Reward: %d, RP Reward: %d\n", PQ_HIT_REWARD_NL, PQ_HIT_REWARD_DHT, PQ_HIT_REWARD_RP);
    printf("  Max Score: %d\n", SCORE_MAX_PQ_HIT);
    printf("  Max Recent Prefetches Tracked per Engine: %zu\n", MAX_RECENT_PF_TRACKING);
    printf("  Initial Phase: EXPLORE. Scores & PQ Tracking reset.\n");
}

void myl1pref::reset_scores_and_pq_tracking() {
    score_nl = 0;
    score_tdc = 0;
    score_src = 0;
    recent_prefetches_nl.clear();
    recent_prefetches_tdc.clear();
    recent_prefetches_src.clear();
}

uint32_t myl1pref::get_aht_index(uint64_t pc) const {
    return pc & (DHT_AHT_NUM_ENTRIES - 1);
}

uint16_t myl1pref::get_aht_tag(uint64_t pc) const {
    return (pc >> DHT_AHT_TAG_INITIAL_SHIFT) & 0xFFFF;
}

uint32_t myl1pref::get_pht_index(const std::array<int16_t, DHT_AHT_DELTA_HISTORY_SIZE>& delta_hist) const {
    uint32_t hash = 1984; 
    hash = hash ^ (static_cast<uint32_t>(delta_hist[0]) << 5);
    hash = hash ^ (static_cast<uint32_t>(delta_hist[1]) << 11);
    hash = hash ^ (static_cast<uint32_t>(delta_hist[2]) << 17);
    hash = hash ^ (hash >> 16); hash = hash ^ (hash << 5);
    return hash & (DHT_PHT_NUM_ENTRIES - 1);
}

uint64_t myl1pref::get_src_region_address(uint64_t block_addr) const {
    return block_addr >> RP_LINES_PER_REGION_LOG2;
}

uint8_t myl1pref::get_src_offset_in_region(uint64_t block_addr) const {
    return static_cast<uint8_t>(block_addr & RP_REGION_MASK);
}

uint32_t myl1pref::get_src_set_index(uint64_t region_addr) const {
    return region_addr & (RP_NUM_SETS - 1);
}

uint64_t myl1pref::get_src_tag(uint64_t region_addr) const {
    return (region_addr >> RP_INDEX_BITS);
}

uint8_t myl1pref::find_src_victim(uint32_t set_idx) const {
    return static_cast<uint8_t>(src_lru_way[set_idx]);
}

void myl1pref::update_src_lru(uint32_t set_idx, bool accessed_way) {
    if (RP_NUM_WAYS == 2) src_lru_way[set_idx] = !accessed_way;
}

void myl1pref::track_issued_prefetch(PrefetchSourceEngine engine_id, uint64_t block_address) {
    std::deque<uint64_t>* tracking_queue = nullptr;
    switch (engine_id) {
        case PrefetchSourceEngine::NL: tracking_queue = &recent_prefetches_nl; break;
        case PrefetchSourceEngine::DHT: tracking_queue = &recent_prefetches_tdc; break;
        case PrefetchSourceEngine::RP: tracking_queue = &recent_prefetches_src; break;
        default: return; 
    }
    if (tracking_queue) {
        tracking_queue->push_front(block_address);
        if (tracking_queue->size() > MAX_RECENT_PF_TRACKING) {
            tracking_queue->pop_back();
        }
    }
}

bool myl1pref::issue_prefetch_wrapper(uint64_t prefetch_address, PrefetchSourceEngine engine_id) {
    champsim::address addr{prefetch_address};
    uint64_t PQ_occupancy = intern_->get_pq_occupancy().back();

    if (PQ_occupancy < MAX_PQ_SIZE) {
        bool success = intern_->prefetch_line(addr, true, static_cast<uint32_t>(engine_id)); 
        if (success) {
            uint64_t prefetch_block_addr = prefetch_address >> LOG2_CACHE_LINE_SIZE;
            track_issued_prefetch(engine_id, prefetch_block_addr);
            switch (engine_id) {
                case PrefetchSourceEngine::NL: num_prefetches_issued_nl++;
                  break;
                case PrefetchSourceEngine::DHT: num_prefetches_issued_tdc++;
                  break;
                case PrefetchSourceEngine::RP: num_prefetches_issued_src++;
                  break;
                case PrefetchSourceEngine::NONE:
                  break;
            }
            return true;
        }
    }
    return false;
}

void myl1pref::check_pq_hits(uint64_t demand_block_address) {

    // CAM
    auto it_nl = std::find(recent_prefetches_nl.begin(), recent_prefetches_nl.end(), demand_block_address);
    if (it_nl != recent_prefetches_nl.end()) {
        score_nl = std::min(SCORE_MAX_PQ_HIT, score_nl + PQ_HIT_REWARD_NL); 
        pq_hits_nl_total++;
        recent_prefetches_nl.erase(it_nl); 
        return; 
    }

    auto it_tdc = std::find(recent_prefetches_tdc.begin(), recent_prefetches_tdc.end(), demand_block_address);
    if (it_tdc != recent_prefetches_tdc.end()) {
        score_tdc = std::min(SCORE_MAX_PQ_HIT, score_tdc + PQ_HIT_REWARD_DHT); 
        pq_hits_tdc_total++;
        recent_prefetches_tdc.erase(it_tdc);
        return;
    }

    auto it_src = std::find(recent_prefetches_src.begin(), recent_prefetches_src.end(), demand_block_address);
    if (it_src != recent_prefetches_src.end()) {
        score_src = std::min(SCORE_MAX_PQ_HIT, score_src + PQ_HIT_REWARD_RP); 
        pq_hits_src_total++;
        recent_prefetches_src.erase(it_src);
        return;
    }
}


void myl1pref::determine_best_engine_for_exploit() {
    // in case of tie, DHT > RP > NL
    
    allowed_tdc = allowed_src = allowed_nl = 0;
    int max_score = -1; 

    if (score_tdc >= max_score) { 
        max_score = score_tdc;
        allowed_tdc = true;
    }

    if (score_src > max_score || score_src > SCORE_THRESHOLD_PREFETCHER) {
        max_score = score_src;
        if (score_tdc < SCORE_THRESHOLD_PREFETCHER)
            allowed_tdc = false;
        allowed_src = true;
    }
    
    if (score_nl > max_score || score_nl > SCORE_THRESHOLD_PREFETCHER) {
        if (score_tdc < SCORE_THRESHOLD_PREFETCHER)
            allowed_tdc = false;
        if (score_src < SCORE_THRESHOLD_PREFETCHER)
            allowed_src = false;
        allowed_nl = true;
    } 

    printf("[%lu] EXPLORE phase ended. PQ Hit Scores: NL=%d, DHT=%d, RP=%d. Selected for EXPLOIT: Engines %d%d%d.\n",
     (intern_->current_time.time_since_epoch() / intern_->clock_period),
           score_nl, score_tdc, score_src, allowed_nl, allowed_tdc, allowed_src);
}

void myl1pref::manage_phase_transitions() {
    phase_cycle_counter++;

    if (current_phase == PrefetcherPhase::PHASE_EXPLORE) {
        if (phase_cycle_counter >= explore_duration_cycles) {
            determine_best_engine_for_exploit();
            current_phase = PrefetcherPhase::PHASE_EXPLOIT;
            phase_cycle_counter = 0;
        }
    } else {
        if (phase_cycle_counter >= exploit_duration_cycles) {
            current_phase = PrefetcherPhase::PHASE_EXPLORE;
            phase_cycle_counter = 0;
            reset_scores_and_pq_tracking(); 
            allowed_tdc = allowed_src = allowed_nl = 0;
        }
    }
}


// Main Cache Operation Logic
uint32_t myl1pref::prefetcher_cache_operate(
    champsim::address addr, champsim::address ip, bool cache_hit, bool useful_prefetch,
    access_type type, uint32_t metadata_in) {

    bool is_demand_access = type == access_type::LOAD;
    uint64_t current_block_addr_val = addr.to<uint64_t>() >> LOG2_CACHE_LINE_SIZE;

    if (is_demand_access) {
        check_pq_hits(current_block_addr_val); 
    }
    
    if (!is_demand_access || ip.to<uint64_t>() == 0) {
        return useful_prefetch ? metadata_in : 0; 
    }

    champsim::address current_pc = ip;

    // Train DHT
    uint32_t aht_idx = get_aht_index(current_pc.to<uint64_t>());
    uint16_t aht_tag_val = get_aht_tag(current_pc.to<uint64_t>());
    DHT_AHT_entry_t& aht_entry = AHT_table[aht_idx];

    if (aht_entry.valid && aht_entry.tag == aht_tag_val) {
        if (aht_entry.last_accessed_block != 0) {
            int16_t current_delta = static_cast<int16_t>(current_block_addr_val - aht_entry.last_accessed_block);

            if (current_delta != 0) {
                uint32_t pht_idx = get_pht_index(aht_entry.delta_history);
                DHT_PHT_entry_t& pht_entry = PHT_table[pht_idx];
                bool pht_tag_match = std::equal(pht_entry.tag_delta_history.begin(), pht_entry.tag_delta_history.end(), aht_entry.delta_history.begin());

                if (pht_entry.valid && pht_tag_match) {
                    if (pht_entry.predicted_next_delta == current_delta) {
                        if (pht_entry.confidence < DHT_PHT_CONFIDENCE_MAX)
                          pht_entry.confidence++;

                    } else { 
                        if (pht_entry.confidence > 0) 
                            pht_entry.confidence--; 
                        else { 
                            pht_entry.predicted_next_delta = current_delta;
                            pht_entry.confidence = 0;
                        }
                    }
                } else {
                    pht_entry.reset();
                    pht_entry.valid = true;
                    pht_entry.tag_delta_history = aht_entry.delta_history;
                    pht_entry.predicted_next_delta = current_delta;
                    pht_entry.confidence = 1; 
                }
                aht_entry.record_new_delta(current_delta);
            }
        }
        aht_entry.last_accessed_block = current_block_addr_val;
    } else {
      aht_entry.reset();
      aht_entry.valid = true;
      aht_entry.tag = aht_tag_val;
      aht_entry.last_accessed_block = current_block_addr_val;
    }

    // Train RP
    uint64_t region_addr_val = get_src_region_address(current_block_addr_val);
    uint32_t src_set_idx = get_src_set_index(region_addr_val);
    uint64_t src_tag_val = get_src_tag(region_addr_val);
    uint8_t offset_in_region = get_src_offset_in_region(current_block_addr_val);
    int src_hit_way = -1;

    for (unsigned i = 0; i < RP_NUM_WAYS; ++i) { 
        if (RP_table[src_set_idx][i].valid && RP_table[src_set_idx][i].region_address_tag == src_tag_val) { 
            src_hit_way = (int)i; 
            break; 
        }
    }
    if (src_hit_way != -1) { 
        RP_table[src_set_idx][(uint32_t)src_hit_way].access_bitmap |= (1U << offset_in_region);
        update_src_lru(src_set_idx, static_cast<bool>(src_hit_way));
    } else {
      uint8_t victim_way = find_src_victim(src_set_idx);
      RP_table[src_set_idx][victim_way].reset();
      RP_table[src_set_idx][victim_way].valid = true;
      RP_table[src_set_idx][victim_way].region_address_tag = src_tag_val;
      RP_table[src_set_idx][victim_way].access_bitmap |= (1U << offset_in_region);
      update_src_lru(src_set_idx, static_cast<bool>(victim_way));
    }


    if (current_phase == PrefetcherPhase::PHASE_EXPLORE) {
        for (unsigned i = 1; i <= nl_prefetch_degree; ++i) {
            uint64_t block_addr_to_prefetch = current_block_addr_val + i;
            if (!issue_prefetch_wrapper(block_addr_to_prefetch << LOG2_CACHE_LINE_SIZE, PrefetchSourceEngine::NL))
              break;
        }

        // DHT Prefetching
        bool tdc_wants_to_prefetch = false; 
        DHT_PHT_entry_t* p_pht_entry = nullptr;

        if (aht_entry.valid && aht_entry.tag == aht_tag_val) { 
            uint32_t pht_idx = get_pht_index(aht_entry.delta_history);
            p_pht_entry = &PHT_table[pht_idx];
            // If valid, check if the tag in the PHT table equals the delta history with which we indexed the entry (potential hash colision)
            if (p_pht_entry->valid &&
                std::equal(p_pht_entry->tag_delta_history.begin(), p_pht_entry->tag_delta_history.end(), aht_entry.delta_history.begin())
                && p_pht_entry->confidence >= 2 &&
                p_pht_entry->predicted_next_delta != 0) {
                tdc_wants_to_prefetch = true;
            }
        }
        if (tdc_wants_to_prefetch && p_pht_entry) {
            uint64_t block_addr_to_prefetch = current_block_addr_val + p_pht_entry->predicted_next_delta;
            issue_prefetch_wrapper(block_addr_to_prefetch << LOG2_CACHE_LINE_SIZE, PrefetchSourceEngine::DHT);
        }

        // RP Prefetching
        bool src_wants_to_prefetch = false;
        RP_entry_t* p_src_entry = nullptr;

        if (src_hit_way != -1) { 
            p_src_entry = &RP_table[src_set_idx][(uint32_t)src_hit_way];
            uint8_t acc_lines = 0;
            for (unsigned i = 0; i < RP_LINES_PER_REGION; ++i)
              if ((p_src_entry->access_bitmap >> i) & 1U)
                acc_lines++;
            if (acc_lines >= RP_ACCESS_DENSITY_THRESHOLD)
              src_wants_to_prefetch = true;
        }
        if (src_wants_to_prefetch && p_src_entry) {
            for (unsigned i = 0; i < RP_LINES_PER_REGION; ++i) {
                if (!((p_src_entry->access_bitmap >> i) & 1U) && !((p_src_entry->prefetch_bitmap >> i) & 1U)) {
                    uint64_t base_region_b_addr = get_src_region_address(current_block_addr_val) << RP_LINES_PER_REGION_LOG2;
                    uint64_t block_addr_to_prefetch = base_region_b_addr + i;
                    if (issue_prefetch_wrapper(block_addr_to_prefetch << LOG2_CACHE_LINE_SIZE, PrefetchSourceEngine::RP)) {
                        p_src_entry->prefetch_bitmap |= (1U << i);
                    } else
                      break;
                }
            }
        }
    } else { // Phase of using the best engine
        if (allowed_nl) {
            for (unsigned i = 1; i <= nl_prefetch_degree; ++i) {
                uint64_t block_addr_to_prefetch = current_block_addr_val + i;
                if (!issue_prefetch_wrapper(block_addr_to_prefetch << LOG2_CACHE_LINE_SIZE, PrefetchSourceEngine::NL))
                  break;
            }
        }
        if (allowed_tdc) {
            bool tdc_wants_to_prefetch = false;
            DHT_PHT_entry_t* p_pht_entry = nullptr;

            if (aht_entry.valid && aht_entry.tag == aht_tag_val) { 
                uint32_t pht_idx = get_pht_index(aht_entry.delta_history);
                p_pht_entry = &PHT_table[pht_idx];

                if (p_pht_entry->valid &&
                    std::equal(p_pht_entry->tag_delta_history.begin(), p_pht_entry->tag_delta_history.end(), aht_entry.delta_history.begin()) &&
                    p_pht_entry->confidence >= 2 &&
                    p_pht_entry->predicted_next_delta != 0) {

                    tdc_wants_to_prefetch = true;
                }
            }

            if (tdc_wants_to_prefetch && p_pht_entry) {
                uint64_t block_addr_to_prefetch = current_block_addr_val + static_cast<int64_t>(p_pht_entry->predicted_next_delta);
                issue_prefetch_wrapper(block_addr_to_prefetch << LOG2_CACHE_LINE_SIZE, PrefetchSourceEngine::DHT);
            }
        }
        if (allowed_src) {
            bool src_wants_to_prefetch = false;
            RP_entry_t* p_src_entry = nullptr;
            if (src_hit_way != -1) { 
                p_src_entry = &RP_table[src_set_idx][(uint32_t)src_hit_way];
                uint8_t acc_lines = 0;

                for (unsigned i = 0; i < RP_LINES_PER_REGION; ++i)
                  if ((p_src_entry->access_bitmap >> i) & 1U)
                    acc_lines++;

                if (acc_lines >= RP_ACCESS_DENSITY_THRESHOLD)
                  src_wants_to_prefetch = true;
            }
            if (src_wants_to_prefetch && p_src_entry) {
                for (unsigned i = 0; i < RP_LINES_PER_REGION; ++i) {
                     if (!((p_src_entry->access_bitmap >> i) & 1U) && !((p_src_entry->prefetch_bitmap >> i) & 1U)) {
                        uint64_t base_region_b_addr = get_src_region_address(current_block_addr_val) << RP_LINES_PER_REGION_LOG2;
                        uint64_t block_addr_to_prefetch = base_region_b_addr + i;

                        if (issue_prefetch_wrapper(block_addr_to_prefetch << LOG2_CACHE_LINE_SIZE, PrefetchSourceEngine::RP)) {
                            p_src_entry->prefetch_bitmap |= (1U << i);
                        } else
                          break;
                    }
                }
            }
        }
    }
    return useful_prefetch ? metadata_in : 0; 
}

uint32_t myl1pref::prefetcher_cache_fill(
    champsim::address addr, uint32_t set, uint32_t way, bool prefetch,
    champsim::address evicted_address, uint32_t metadata_in) {

    return metadata_in;
}

void myl1pref::prefetcher_cycle_operate() {
    manage_phase_transitions(); 

    uint64_t current_cycle = (uint64_t) (intern_->current_time.time_since_epoch() / intern_->clock_period);
    uint64_t confidence_decay_interval = 256000; 
    // Decay with time
    if ((current_cycle % confidence_decay_interval) == 0 && current_cycle > 0) {
        for (auto& entry : PHT_table) if (entry.confidence > 0) entry.confidence--;
        for (auto& set : RP_table) for (auto& way_entry : set) way_entry.prefetch_bitmap = 0;
        
    }
}

void myl1pref::prefetcher_final_stats() {
    std::cout << "Hybrid Prefetcher Final Statistics (Phased Explore/Exploit v7.2 - NL, DHT, RP):" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    auto print_engine_stats = [](const std::string& name, uint64_t issued, uint64_t useful_champsim, uint64_t pq_hits) { 
        std::cout << name << " Engine:" << std::endl;
        std::cout << "  Prefetches Issued: " << issued << std::endl;
        std::cout << "  PQ Hits (Used for Score): " << pq_hits << std::endl;
        if (issued > 0) {
            std::cout << "  PQ Hit Rate: " << std::fixed << std::setprecision(2) << (100.0 * (double)pq_hits / (double)issued) << "%" << std::endl;
        } else {
            std::cout << "  PQ Hit Rate: N/A" << std::endl;
        }
        std::cout << "  Useful by ChampSim (metadata match): " << useful_champsim << std::endl;
         if (issued > 0 && useful_champsim >0) { 
            std::cout << "  Accuracy (ChampSim useful / Issued): " << std::fixed << std::setprecision(2) << (100.0 * (double)useful_champsim / (double)issued) << "%" << std::endl;
        } else {
            std::cout << "  Accuracy (ChampSim useful / Issued): N/A" << std::endl;
        }
    };
    print_engine_stats("NL ", num_prefetches_issued_nl,  num_prefetches_useful_nl,  pq_hits_nl_total); // Updated
    print_engine_stats("DHT", num_prefetches_issued_tdc, num_prefetches_useful_tdc, pq_hits_tdc_total);
    print_engine_stats("RP", num_prefetches_issued_src, num_prefetches_useful_src, pq_hits_src_total);

    uint64_t total_issued = num_prefetches_issued_nl + num_prefetches_issued_tdc + num_prefetches_issued_src; // Updated
    uint64_t total_pq_hits = pq_hits_nl_total + pq_hits_tdc_total + pq_hits_src_total; // Updated
    
    std::cout << "Overall:" << std::endl;
    std::cout << "  Total Prefetches Issued: " << total_issued << std::endl;
    std::cout << "  Total PQ Hits (all engines): " << total_pq_hits << std::endl;
    if (total_issued > 0) {
        std::cout << "  Overall PQ Hit Rate: " << std::fixed << std::setprecision(2) << (100.0 * (double)total_pq_hits / (double)total_issued) << "%" << std::endl;
    } else {
        std::cout << "  Overall PQ Hit Rate: N/A" << std::endl;
    }
    std::cout << "  Total Useful by ChampSim (any metadata): " << num_prefetches_useful_total_champsim << std::endl;
    uint64_t total_useful_by_our_engines_champsim = num_prefetches_useful_nl + num_prefetches_useful_tdc + num_prefetches_useful_src; // Updated
     if (total_issued > 0) {
        std::cout << "  Overall Accuracy (ChampSim useful from our engines / Issued): " << std::fixed << std::setprecision(2) << (100.0 * (double)total_useful_by_our_engines_champsim / (double)total_issued) << "%" << std::endl;
    } else {
        std::cout << "  Overall Accuracy (ChampSim useful from our engines / Issued): N/A" << std::endl;
    }
    std::cout << "------------------------------------" << std::endl;
}

#ifdef APG_WITH_HYPERSCAN

#include "hs_backend.h"

namespace apg {

namespace {

class HsScratch : public BackendScratch {
public:
    HsScratch() : scratch_(nullptr) {}
    ~HsScratch() override {
        if (scratch_ != nullptr) hs_free_scratch(scratch_);
    }
    HsScratch(const HsScratch&) = delete;
    HsScratch& operator=(const HsScratch&) = delete;
    hs_scratch_t* scratch_;
};

struct ScanCtx {
    const RuleSetData* data;
    std::vector<Candidate>* out;
    size_t max_hits;
    bool overflow;
    CandidateSink* sink;
    size_t seen;
};

int on_match(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* vctx) {
    (void)from;   // Without SOM the start offset is not meaningful: only the END offset is used.
    (void)flags;
    ScanCtx* ctx = static_cast<ScanCtx*>(vctx);
    const auto it = ctx->data->pattern_index_by_id.find(static_cast<uint32_t>(id));
    if (it == ctx->data->pattern_index_by_id.end()) return 0;   // not one of ours: ignore
    if ((ctx->sink != nullptr ? ctx->seen : ctx->out->size()) >= ctx->max_hits) {
        ctx->overflow = true;
        return 1;                                                  // non-zero stops the scan
    }
    const PatternDef& p = ctx->data->patterns[static_cast<size_t>(it->second)];
    Candidate c;
    c.pattern_index = static_cast<uint32_t>(it->second);
    c.end = static_cast<uint64_t>(to);
    c.exact = (p.cls == PatternClass::Native);
    if (ctx->sink != nullptr) {
        ++ctx->seen;
        return ctx->sink->on_candidate(c) ? 1 : 0;                 // the caller has what it wanted: stop the scan
    }
    ctx->out->push_back(c);
    return 0;
}

}  // namespace

HsBackend::HsBackend(const RuleSetData& data, std::vector<std::vector<hs_database_t*>> dbs_by_profile)
    : data_(data), dbs_(std::move(dbs_by_profile)) {}

HsBackend::~HsBackend() {
    for (const std::vector<hs_database_t*>& shards : dbs_) {
        for (hs_database_t* db : shards) {
            if (db != nullptr) hs_free_database(db);
        }
    }
}

std::unique_ptr<BackendScratch> HsBackend::new_scratch() const {
    std::unique_ptr<HsScratch> sc(new HsScratch());
    for (const std::vector<hs_database_t*>& shards : dbs_) {
        for (hs_database_t* db : shards) {
            if (db == nullptr) continue;
            // hs_alloc_scratch grows an existing scratch so that one scratch space serves every database.
            const hs_error_t e = hs_alloc_scratch(db, &sc->scratch_);
            if (e == HS_NOMEM) throw Error(Status::Oom, "Hyperscan: out of memory allocating scratch space");
            if (e != HS_SUCCESS) throw Error(Status::Internal, "Hyperscan: hs_alloc_scratch failed (" + std::to_string(e) + ")");
        }
    }
    return std::unique_ptr<BackendScratch>(sc.release());
}

bool HsBackend::scan(int profile, const char* data, size_t len, BackendScratch& scratch, std::vector<Candidate>& out,
                     size_t max_hits, CandidateSink* sink) const {
    if (profile < 0 || static_cast<size_t>(profile) >= dbs_.size()) return true;
    const std::vector<hs_database_t*>& shards = dbs_[static_cast<size_t>(profile)];
    if (shards.empty()) return true;
    if (len > 0xFFFFFFFFull) throw Error(Status::Limit, "text longer than 4 GiB cannot be scanned");
    HsScratch& sc = static_cast<HsScratch&>(scratch);
    ScanCtx ctx;
    ctx.data = &data_;
    ctx.out = &out;
    ctx.max_hits = max_hits;
    ctx.overflow = false;
    ctx.sink = sink;
    ctx.seen = 0;
    // Every shard sees the same text; a pattern lives in exactly one shard, so no candidate appears twice.
    for (hs_database_t* db : shards) {
        if (db == nullptr) continue;
        const hs_error_t e = hs_scan(db, data, static_cast<unsigned int>(len), 0, sc.scratch_, on_match, &ctx);
        if (e == HS_SUCCESS) continue;
        if (e == HS_SCAN_TERMINATED) return !ctx.overflow;
        throw Error(Status::Internal, "Hyperscan: hs_scan failed (" + std::to_string(e) + ")");
    }
    return true;
}

hs_database_t* HsBackend::deserialize(const std::string& bytes) {
    hs_database_t* db = nullptr;
    const hs_error_t e = hs_deserialize_database(bytes.data(), bytes.size(), &db);
    if (e == HS_SUCCESS) return db;
    if (e == HS_DB_VERSION_ERROR) {
        throw Error(Status::Version, "the Hyperscan database was built by another Hyperscan version than the one "
                                     "this engine is linked with (" + library_version() + ")");
    }
    if (e == HS_DB_PLATFORM_ERROR) {
        throw Error(Status::Platform, "the Hyperscan database was built for CPU features this machine does not have");
    }
    if (e == HS_NOMEM) throw Error(Status::Oom, "out of memory deserialising the Hyperscan database");
    throw Error(Status::Database, "the Hyperscan database is corrupt (hs_deserialize_database returned " +
                                      std::to_string(e) + ")");
}

std::string HsBackend::library_version() {
    const char* v = hs_version();
    return v ? std::string(v) : std::string("unknown");
}

}  // namespace apg

#endif  // APG_WITH_HYPERSCAN

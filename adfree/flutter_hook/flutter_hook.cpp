#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <link.h>

#include <string>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#define TAG "FlutterHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

// Dictionary mapping UTF-8 source string -> UTF-8 translated string
static std::unordered_map<std::string, std::string> g_dict;
static pthread_rwlock_t g_dict_lock = PTHREAD_RWLOCK_INITIALIZER;

// Original virtual dispatch function
typedef void (*AddTextFn)(void* builder, const std::u16string* text);
static AddTextFn g_orig_addText = nullptr;
static uintptr_t g_callsite_addr = 0;
static void* g_trampoline_page = nullptr;

// -----------------------------------------------------------------------------
// Unicode conversion helpers
// -----------------------------------------------------------------------------
static std::string u16_to_u8(const char16_t* u16, size_t len) {
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        char32_t c = u16[i];
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < len) {
            char32_t c2 = u16[i + 1];
            if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                c = (((c - 0xD800) << 10) | (c2 - 0xDC00)) + 0x10000;
                ++i;
            }
        }
        if (c <= 0x7F) {
            out.push_back((char)c);
        } else if (c <= 0x7FF) {
            out.push_back((char)(0xC0 | ((c >> 6) & 0x1F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        } else if (c <= 0xFFFF) {
            out.push_back((char)(0xE0 | ((c >> 12) & 0x0F)));
            out.push_back((char)(0x80 | ((c >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        } else {
            out.push_back((char)(0xF0 | ((c >> 18) & 0x07)));
            out.push_back((char)(0x80 | ((c >> 12) & 0x3F)));
            out.push_back((char)(0x80 | ((c >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

static std::u16string u8_to_u16(const std::string& u8) {
    std::u16string out;
    out.reserve(u8.size());
    size_t i = 0;
    while (i < u8.size()) {
        unsigned char c = (unsigned char)u8[i++];
        char32_t code = 0;
        int remaining = 0;
        if (c <= 0x7F) {
            code = c;
        } else if ((c & 0xE0) == 0xC0) {
            code = c & 0x1F;
            remaining = 1;
        } else if ((c & 0xF0) == 0xE0) {
            code = c & 0x0F;
            remaining = 2;
        } else if ((c & 0xF8) == 0xF0) {
            code = c & 0x07;
            remaining = 3;
        }
        while (remaining-- > 0 && i < u8.size()) {
            code = (code << 6) | ((unsigned char)u8[i++] & 0x3F);
        }
        if (code <= 0xFFFF) {
            out.push_back((char16_t)code);
        } else {
            code -= 0x10000;
            out.push_back((char16_t)(0xD800 + ((code >> 10) & 0x3FF)));
            out.push_back((char16_t)(0xDC00 + (code & 0x3FF)));
        }
    }
    return out;
}

// -----------------------------------------------------------------------------
// Hook Callback: intercept ParagraphBuilder.addText
// -----------------------------------------------------------------------------
static void call_orig_addText(void* builder, const std::u16string* text) {
    if (!builder || !text) return;
    void** vtable = *(void***)builder;
    if (vtable) {
        auto fn = (void(*)(void*, const std::u16string*))vtable[5]; // vtable + 0x28
        if (fn) {
            fn(builder, text);
            return;
        }
    }
    if (g_orig_addText) {
#if defined(__aarch64__)
        uintptr_t vt = *(uintptr_t*)builder;
        register uintptr_t r_x8 __asm__("x8") = vt;
        asm volatile("" : : "r"(r_x8));
#endif
        g_orig_addText(builder, text);
    }
}

extern "C" void Hooked_AddText(void* builder, const std::u16string* text) {
    if (!builder || !text || text->empty()) {
        call_orig_addText(builder, text);
        return;
    }

    std::string original_u8 = u16_to_u8(text->data(), text->size());

    pthread_rwlock_rdlock(&g_dict_lock);
    auto it = g_dict.find(original_u8);
    std::string replacement;
    bool found = (it != g_dict.end());
    if (found) {
        replacement = it->second;
    }
    pthread_rwlock_unlock(&g_dict_lock);

    if (found && !replacement.empty()) {
        LOGI("Hooked: '%s' -> '%s'", original_u8.c_str(), replacement.c_str());
        std::u16string new_text = u8_to_u16(replacement);
        call_orig_addText(builder, &new_text);
    } else {
        call_orig_addText(builder, text);
    }
}

// -----------------------------------------------------------------------------
// Memory scanning and Hook installation
// -----------------------------------------------------------------------------
struct LoadSegment {
    uintptr_t start = 0;
    size_t size = 0;
    uint32_t flags = 0;
};

struct PhdrCtx {
    uintptr_t base = 0;
    std::string path;
    std::vector<LoadSegment> segments;
    bool found = false;
};

static int phdr_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* ctx = (PhdrCtx*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, "libflutter.so")) {
        ctx->base = (uintptr_t)info->dlpi_addr;
        ctx->path = info->dlpi_name;
        ctx->found = true;
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_LOAD) {
                LoadSegment seg;
                seg.start = ctx->base + info->dlpi_phdr[i].p_vaddr;
                seg.size = (size_t)info->dlpi_phdr[i].p_filesz;
                seg.flags = (uint32_t)info->dlpi_phdr[i].p_flags;
                if (seg.size > 0) {
                    ctx->segments.push_back(seg);
                }
            }
        }
        return 1;
    }
    return 0;
}

static bool find_libflutter(uintptr_t& base, std::vector<LoadSegment>& segments, std::string& path) {
    // 1. Dùng dl_iterate_phdr
    PhdrCtx ctx;
    dl_iterate_phdr(phdr_cb, &ctx);
    if (ctx.found && !ctx.segments.empty()) {
        base = ctx.base;
        path = ctx.path;
        segments = ctx.segments;
        LOGI("dl_iterate_phdr found libflutter at 0x%lx with %zu segments: %s",
             (unsigned long)base, segments.size(), path.c_str());
        return true;
    }

    // 2. Thử dlopen RTLD_NOLOAD
    void* handle = dlopen("libflutter.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        dlclose(handle);
        dl_iterate_phdr(phdr_cb, &ctx);
        if (ctx.found && !ctx.segments.empty()) {
            base = ctx.base;
            path = ctx.path;
            segments = ctx.segments;
            LOGI("dl_iterate_phdr (after dlopen) found libflutter at 0x%lx with %zu segments: %s",
                 (unsigned long)base, segments.size(), path.c_str());
            return true;
        }
    }

    // 3. Fallback quét /proc/self/maps
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;

    char line[512];
    bool found = false;
    uintptr_t start = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libflutter.so")) {
            char perms[16], path_buf[256];
            uintptr_t s, e;
            if (sscanf(line, "%lx-%lx %15s %*s %*s %*s %255s", &s, &e, perms, path_buf) >= 3) {
                if (!found) {
                    start = s;
                    path = path_buf;
                    found = true;
                }
                LoadSegment seg;
                seg.start = s;
                seg.size = (size_t)(e - s);
                seg.flags = 0;
                if (perms[0] == 'r') seg.flags |= PF_R;
                if (perms[1] == 'w') seg.flags |= PF_W;
                if (perms[2] == 'x') seg.flags |= PF_X;
                segments.push_back(seg);
            }
        }
    }
    fclose(fp);

    if (found && !segments.empty()) {
        base = start;
        LOGI("proc maps found libflutter at 0x%lx with %zu segments: %s",
             (unsigned long)base, segments.size(), path.c_str());
        return true;
    }
    return false;
}

static bool install_flutter_hook() {
    uintptr_t base = 0;
    std::vector<LoadSegment> segments;
    std::string path;

    if (!find_libflutter(base, segments, path)) {
        return false;
    }

    // 1. Scan for string "ParagraphBuilder::addText\0" in readable segments
    const char target_str[] = "ParagraphBuilder::addText";
    const size_t target_len = sizeof(target_str);

    uintptr_t str_va = 0;
    for (const auto& seg : segments) {
        if (!(seg.flags & PF_R) || seg.size < target_len) continue;
        const void* found = memmem((const void*)seg.start, seg.size, target_str, target_len);
        if (found) {
            str_va = (uintptr_t)found;
            break;
        }
    }

    if (!str_va) {
        LOGE("String 'ParagraphBuilder::addText' not found in libflutter.so");
        return false;
    }
    LOGI("Found target string at VA: 0x%lx", (unsigned long)str_va);

    // 2. Find xref in executable segments
    uintptr_t target_page = str_va & ~0xFFFULL;
    uint32_t target_page_off = (uint32_t)(str_va & 0xFFFU);
    uintptr_t xref_pc = 0;

    for (const auto& seg : segments) {
        if (!(seg.flags & PF_X) || seg.size < 8) continue;
        const uint8_t* mem = (const uint8_t*)seg.start;
        for (size_t i = 0; i + 8 <= seg.size; i += 4) {
            uint32_t inst = *(const uint32_t*)(mem + i);
            // ADRP: [1][immlo:2][10000][immhi:19][Rd:5]
            if ((inst & 0x9F000000) == 0x90000000) {
                int64_t immlo = (inst >> 29) & 0x3;
                int64_t immhi = (inst >> 5) & 0x7FFFF;
                int64_t imm = (immhi << 2) | immlo;
                if (imm & (1 << 20)) imm -= (1 << 21);

                uintptr_t pc = seg.start + i;
                uintptr_t pc_page = pc & ~0xFFFULL;
                uintptr_t calc_page = pc_page + (imm << 12);

                if (calc_page == target_page) {
                    uint32_t rd = inst & 0x1F;
                    uint32_t next_inst = *(const uint32_t*)(mem + i + 4);
                    // ADD (imm64): 1001000100 [imm12] [Rn] [Rd]
                    if ((next_inst & 0xFFC00000) == 0x91000000) {
                        uint32_t rn = (next_inst >> 5) & 0x1F;
                        uint32_t imm12 = (next_inst >> 10) & 0xFFF;
                        if (rn == rd && imm12 == target_page_off) {
                            xref_pc = pc;
                            break;
                        }
                    }
                }
            }
        }
        if (xref_pc) break;
    }

    if (!xref_pc) {
        LOGE("Could not find xref to ParagraphBuilder::addText");
        return false;
    }
    LOGI("Found xref at VA: 0x%lx", xref_pc);

    // 3. Find wrapper function via ADR instruction within 40 bytes after xref
    uintptr_t wrapper_va = 0;
    for (int j = 4; j <= 40; j += 4) {
        uintptr_t curr_pc = xref_pc + j;
        uint32_t inst = *(const uint32_t*)curr_pc;
        // ADR: 0 [immlo:2] 10000 [immhi:19] [Rd:5]
        if ((inst & 0x9F000000) == 0x10000000) {
            int64_t immlo = (inst >> 29) & 0x3;
            int64_t immhi = (inst >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & (1 << 20)) imm -= (1 << 21);
            wrapper_va = curr_pc + imm;
            break;
        }
    }

    if (!wrapper_va) {
        LOGE("Could not find wrapper function address from xref");
        return false;
    }
    LOGI("Found wrapper function at VA: 0x%lx", wrapper_va);

    // 4. In wrapper function, find the BL instruction that dispatches the call
    uintptr_t bl_call_va = 0;
    uintptr_t orig_target = 0;

    for (int k = 0; k < 200; k += 4) {
        uintptr_t pc = wrapper_va + k;
        uint32_t inst = *(const uint32_t*)pc;
        // BL: 100101 [imm26]
        if ((inst & 0xFC000000) == 0x94000000) {
            uint32_t prev2 = *(const uint32_t*)(pc - 8);
            // ADD x1, sp, #imm
            if ((prev2 & 0xFF00001F) == 0x91000001) {
                int64_t imm26 = inst & 0x3FFFFFF;
                if (imm26 & (1 << 25)) imm26 -= (1 << 26);
                orig_target = pc + (imm26 << 2);
                bl_call_va = pc;
                break;
            }
        }
    }

    if (!bl_call_va || !orig_target) {
        LOGE("Could not locate addText BL callsite in wrapper");
        return false;
    }
    LOGI("Found BL callsite at VA: 0x%lx -> target: 0x%lx", bl_call_va, orig_target);

    g_orig_addText = (AddTextFn)orig_target;
    g_callsite_addr = bl_call_va;

    // 5. Allocate executable trampoline page near libflutter (< 128 MB)
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

    void* stub_page = MAP_FAILED;
    for (int64_t delta = 0x100000; delta < 120LL * 1024 * 1024; delta += 0x10000) {
        uintptr_t try_addr = (bl_call_va + delta) & ~0xFFFULL;
        stub_page = mmap((void*)try_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (stub_page != MAP_FAILED) {
            LOGI("Allocated stub page at 0x%lx (delta +0x%lx)", (unsigned long)try_addr, (unsigned long)delta);
            break;
        }

        try_addr = (bl_call_va - delta) & ~0xFFFULL;
        stub_page = mmap((void*)try_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (stub_page != MAP_FAILED) {
            LOGI("Allocated stub page at 0x%lx (delta -0x%lx)", (unsigned long)try_addr, (unsigned long)delta);
            break;
        }
    }

    if (stub_page == MAP_FAILED) {
        LOGE("Failed to allocate executable stub page within 128 MB");
        return false;
    }

    g_trampoline_page = stub_page;

    // In stub_page, emit:
    //   LDR X16, #8
    //   BR X16
    //   .quad Hooked_AddText
    uint32_t* stub_code = (uint32_t*)stub_page;
    stub_code[0] = 0x58000050; // ldr x16, #8
    stub_code[1] = 0xD61F0200; // br x16
    *(uint64_t*)(stub_code + 2) = (uint64_t)Hooked_AddText;

    __builtin___clear_cache((char*)stub_page, (char*)stub_page + 32);

    // 6. Patch BL instruction at bl_call_va to jump to stub_page
    uintptr_t page_to_patch = bl_call_va & ~0xFFFULL;
    if (mprotect((void*)page_to_patch, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed on libflutter code page");
        return false;
    }

    int64_t offset = (uintptr_t)stub_page - bl_call_va;
    uint32_t imm26 = (uint32_t)((offset >> 2) & 0x3FFFFFF);
    uint32_t new_bl = 0x94000000 | imm26;

    *(uint32_t*)bl_call_va = new_bl;
    __builtin___clear_cache((char*)bl_call_va, (char*)bl_call_va + 4);

    LOGI("🎉 Successfully hooked ParagraphBuilder.addText at 0x%lx!", bl_call_va);
    return true;
}

// -----------------------------------------------------------------------------
// Dictionary Loader
// -----------------------------------------------------------------------------
static void parse_json_dict(const std::string& json_str) {
    // Simple JSON key-value parser for {"key": "val", ...}
    size_t pos = 0;
    int count = 0;
    while (pos < json_str.size()) {
        size_t k_start = json_str.find('"', pos);
        if (k_start == std::string::npos) break;
        size_t k_end = json_str.find('"', k_start + 1);
        while (k_end != std::string::npos && json_str[k_end - 1] == '\\') {
            k_end = json_str.find('"', k_end + 1);
        }
        if (k_end == std::string::npos) break;

        size_t colon = json_str.find(':', k_end + 1);
        if (colon == std::string::npos) break;

        size_t v_start = json_str.find('"', colon + 1);
        if (v_start == std::string::npos) break;
        size_t v_end = json_str.find('"', v_start + 1);
        while (v_end != std::string::npos && json_str[v_end - 1] == '\\') {
            v_end = json_str.find('"', v_end + 1);
        }
        if (v_end == std::string::npos) break;

        std::string key = json_str.substr(k_start + 1, k_end - k_start - 1);
        std::string val = json_str.substr(v_start + 1, v_end - v_start - 1);

        // unescape \" and \\ and \n
        auto unescape = [](std::string& s) {
            std::string out;
            out.reserve(s.size());
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '\\' && i + 1 < s.size()) {
                    char next = s[++i];
                    if (next == 'n') out.push_back('\n');
                    else if (next == 'r') out.push_back('\r');
                    else if (next == 't') out.push_back('\t');
                    else out.push_back(next);
                } else {
                    out.push_back(s[i]);
                }
            }
            s = out;
        };
        unescape(key);
        unescape(val);

        pthread_rwlock_wrlock(&g_dict_lock);
        g_dict[key] = val;
        pthread_rwlock_unlock(&g_dict_lock);

        count++;
        pos = v_end + 1;
    }
    LOGI("Loaded %d translation pairs into dictionary", count);
}

static void load_dictionary() {
    // 1. Check /data/local/tmp/flutter_dict.json first (developer override)
    FILE* fp = fopen("/data/local/tmp/flutter_dict.json", "rb");
    if (!fp) {
        // 2. Try to find the base APK and extract assets/flutter_dict.json
        FILE* maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, "base.apk") || strstr(line, ".apk")) {
                    char path[256];
                    if (sscanf(line, "%*s %*s %*s %*s %*s %255s", path) == 1) {
                        if (access(path, R_OK) == 0) {
                            // Try opening APK as zip
                            int fd = open(path, O_RDONLY);
                            if (fd >= 0) {
                                off_t fsize = lseek(fd, 0, SEEK_END);
                                // Search backwards for End of Central Directory (0x06054b50)
                                size_t search_len = fsize > 65536 ? 65536 : fsize;
                                lseek(fd, fsize - search_len, SEEK_SET);
                                std::vector<uint8_t> buf(search_len);
                                if (read(fd, buf.data(), search_len) == (ssize_t)search_len) {
                                    for (ssize_t i = search_len - 22; i >= 0; --i) {
                                        if (*(uint32_t*)&buf[i] == 0x06054B50) {
                                            uint32_t cd_off = *(uint32_t*)&buf[i + 16];
                                            uint16_t cd_count = *(uint16_t*)&buf[i + 10];
                                            lseek(fd, cd_off, SEEK_SET);
                                            std::vector<uint8_t> cd_buf(fsize - search_len + i - cd_off);
                                            read(fd, cd_buf.data(), cd_buf.size());
                                            
                                            size_t p = 0;
                                            for (int c = 0; c < cd_count && p + 46 <= cd_buf.size(); ++c) {
                                                if (*(uint32_t*)&cd_buf[p] != 0x02014B50) break;
                                                uint16_t method = *(uint16_t*)&cd_buf[p + 10];
                                                uint32_t comp_size = *(uint32_t*)&cd_buf[p + 20];
                                                uint32_t uncomp_size = *(uint32_t*)&cd_buf[p + 24];
                                                uint16_t name_len = *(uint16_t*)&cd_buf[p + 28];
                                                uint16_t extra_len = *(uint16_t*)&cd_buf[p + 30];
                                                uint16_t comment_len = *(uint16_t*)&cd_buf[p + 32];
                                                uint32_t local_off = *(uint32_t*)&cd_buf[p + 42];

                                                std::string fname((char*)&cd_buf[p + 46], name_len);
                                                if (fname == "assets/flutter_dict.json") {
                                                    LOGI("Found assets/flutter_dict.json in %s (size %u)", path, uncomp_size);
                                                    // Local file header: 30 + name + EXTRA (extra có thể khác CD)
                                                    uint8_t local_hdr[30];
                                                    if (lseek(fd, local_off, SEEK_SET) < 0 ||
                                                        read(fd, local_hdr, 30) != 30 ||
                                                        *(uint32_t*)local_hdr != 0x04034B50) {
                                                        LOGW("Bad local header for flutter_dict.json");
                                                        p += 46 + name_len + extra_len + comment_len;
                                                        continue;
                                                    }
                                                    uint16_t loc_name_len = *(uint16_t*)&local_hdr[26];
                                                    uint16_t loc_extra_len = *(uint16_t*)&local_hdr[28];
                                                    uint16_t loc_method = *(uint16_t*)&local_hdr[8];
                                                    uint32_t loc_comp = *(uint32_t*)&local_hdr[18];
                                                    uint32_t loc_uncomp = *(uint32_t*)&local_hdr[22];
                                                    if (loc_comp == 0xFFFFFFFF || loc_uncomp == 0xFFFFFFFF) {
                                                        // Zip64 — hiếm với dict JSON; bỏ qua
                                                        LOGW("Zip64 flutter_dict.json not supported");
                                                        p += 46 + name_len + extra_len + comment_len;
                                                        continue;
                                                    }
                                                    off_t data_off = (off_t)local_off + 30 + loc_name_len + loc_extra_len;
                                                    if (lseek(fd, data_off, SEEK_SET) < 0) {
                                                        p += 46 + name_len + extra_len + comment_len;
                                                        continue;
                                                    }
                                                    std::vector<uint8_t> comp_data(loc_comp);
                                                    if (read(fd, comp_data.data(), loc_comp) != (ssize_t)loc_comp) {
                                                        LOGW("Short read flutter_dict.json");
                                                        p += 46 + name_len + extra_len + comment_len;
                                                        continue;
                                                    }

                                                    std::string json_content;
                                                    if (loc_method == 0) { // STORED
                                                        json_content.assign((char*)comp_data.data(), loc_comp);
                                                    } else if (loc_method == 8) { // DEFLATE
                                                        json_content.resize(loc_uncomp);
                                                        z_stream strm = {};
                                                        strm.next_in = comp_data.data();
                                                        strm.avail_in = loc_comp;
                                                        strm.next_out = (Bytef*)json_content.data();
                                                        strm.avail_out = loc_uncomp;
                                                        if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
                                                            LOGW("inflateInit2 failed");
                                                            p += 46 + name_len + extra_len + comment_len;
                                                            continue;
                                                        }
                                                        int zrc = inflate(&strm, Z_FINISH);
                                                        inflateEnd(&strm);
                                                        if (zrc != Z_STREAM_END) {
                                                            LOGW("inflate flutter_dict failed: %d", zrc);
                                                            p += 46 + name_len + extra_len + comment_len;
                                                            continue;
                                                        }
                                                        json_content.resize(strm.total_out);
                                                    } else {
                                                        LOGW("Unsupported zip method %u for flutter_dict", loc_method);
                                                        p += 46 + name_len + extra_len + comment_len;
                                                        continue;
                                                    }
                                                    parse_json_dict(json_content);
                                                    close(fd);
                                                    fclose(maps);
                                                    return;
                                                }
                                                p += 46 + name_len + extra_len + comment_len;
                                            }
                                            break;
                                        }
                                    }
                                }
                                close(fd);
                            }
                        }
                    }
                }
            }
            fclose(maps);
        }
        return;
    }

    // Read from /data/local/tmp/flutter_dict.json
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string content(sz, '\0');
    fread(&content[0], 1, sz, fp);
    fclose(fp);
    LOGI("Loaded dictionary from /data/local/tmp/flutter_dict.json (%ld bytes)", sz);
    parse_json_dict(content);
}

// -----------------------------------------------------------------------------
// Background Thread to wait for libflutter.so and install hook
// -----------------------------------------------------------------------------
static void* hook_thread_main(void*) {
    LOGI("FlutterHook background monitoring thread started");
    load_dictionary();

    for (int retry = 0; retry < 60; ++retry) {
        if (install_flutter_hook()) {
            LOGI("FlutterHook installed successfully!");
            return nullptr;
        }
        usleep(100 * 1000); // 100ms
    }

    LOGW("Timeout waiting for libflutter.so");
    return nullptr;
}

// -----------------------------------------------------------------------------
// JNI Entry Point
// -----------------------------------------------------------------------------
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("libflutter_hook.so JNI_OnLoad called");

    pthread_t th;
    pthread_create(&th, nullptr, hook_thread_main, nullptr);
    pthread_detach(th);

    return JNI_VERSION_1_6;
}

// Support manual dictionary update from Java if needed
extern "C" JNIEXPORT void JNICALL
Java_com_adfree_FlutterHook_setTranslation(JNIEnv* env, jclass clazz, jstring jsrc, jstring jdst) {
    if (!jsrc || !jdst) return;
    const char* src = env->GetStringUTFChars(jsrc, nullptr);
    const char* dst = env->GetStringUTFChars(jdst, nullptr);
    pthread_rwlock_wrlock(&g_dict_lock);
    g_dict[src] = dst;
    pthread_rwlock_unlock(&g_dict_lock);
    env->ReleaseStringUTFChars(jsrc, src);
    env->ReleaseStringUTFChars(jdst, dst);
}

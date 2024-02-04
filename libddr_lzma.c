/* libddr_lzma.c
 *
 * plugin for dd_rescue, doing compression and decompression for xz archives.
 *
 * (c) Dmitrii Ivanov <dsivanov_9@edu.hse.ru>, 2023
 * License: GNU GPLv2 or v3
 */
#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <lzma.h>

#define CHUNK_SIZE 32768

/* fwd decl */
extern ddr_plugin_t ddr_plug;

enum compmode {
    AUTO=0,
    TEST,
    COMPRESS,
    DECOMPRESS
};

enum check_type {
    NONE,
    CRC32,
    CRC64,
    SHA256,
    UNDEFINED
};

typedef struct _lzma_state {
    uint8_t input_bf[CHUNK_SIZE + 1];
    uint8_t output_bf[CHUNK_SIZE + 1];
    size_t pos;
    enum compmode mode;
    enum check_type type;
    uint32_t preset;
    unsigned char *output;
    size_t file_size;
    size_t buf_len;
    size_t readed;
    lzma_stream strm;
    const opt_t *opts;
    bool do_bench;
    bool is_finished;
    bool is_mt;
    clock_t cpu;
    int seq;
} lzma_state;

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

const char* lzma_help = "LZMA plugin which is doing compression/decompression for xz archives.\n"
                        " Parameters:\n"
                        " z - compress input file,\n"
                        " d - decompress input file,\n"
                        " test - check archive integrity,\n"
                        " preset=0...9 - compression preset, default is 6,\n"
                        " check=CRC32/CRC64/SHA256/NONE - select checksum to calculate when compression, CRC32 by default,\n"
                        " bench - calculate time spent on (de)compression.\n";

lzma_check get_lzma_check_flag(enum check_type type)
{
    switch (type) {
        case CRC32:
            return LZMA_CHECK_CRC32;
        case CRC64:
            return LZMA_CHECK_CRC64;
        case SHA256:
            return LZMA_CHECK_SHA256;
        default:
            return LZMA_CHECK_NONE;
    }
}

lzma_bool is_check_supported(enum check_type type)
{
    return lzma_check_is_supported(get_lzma_check_flag(type));
}

lzma_ret init_lzma_stream(lzma_state* state) {
    if (!is_check_supported(state->type)) {
        FPLOG(FATAL, "This type of integrity check is not supported by llzma yet!\n");
        return LZMA_UNSUPPORTED_CHECK;
    }

    int threads = lzma_cputhreads();
    if (threads == 0) {
        threads = 1;
    }

    if (state->mode == COMPRESS) {
        if (state->is_mt) {
            lzma_mt options = {
                .threads=threads,
                .block_size=0,
                .timeout=0,
                .preset=state->preset,
                .filters=NULL,
                .check=state->type
            };
            return lzma_stream_encoder_mt(&(state->strm), &options);
        }
        return lzma_easy_encoder(&(state->strm), state->preset, get_lzma_check_flag(state->type));
    }

    uint32_t flags = LZMA_CONCATENATED | LZMA_TELL_UNSUPPORTED_CHECK;
    if (state->is_mt) {
        lzma_mt options = {
            .flags=flags,
            .threads=threads,
            .timeout=0,
            .filters=NULL,
            .memlimit_threading=lzma_physmem() / 4
        };
        return lzma_stream_decoder_mt(&(state->strm), &options);
    }
    return lzma_auto_decoder(&(state->strm), lzma_physmem() / 4, flags);
}

enum check_type get_check_type(char* param)
{
    if (!strcmp(param, "CRC32")) {
        return CRC32;
    }
    if (!strcmp(param, "CRC64")) {
        return CRC64;
    }
    if (!strcmp(param, "SHA256")) {
        return SHA256;
    }
    if (!strcmp(param, "NONE")) {
        return NONE;
    }
    return UNDEFINED;
}

int lzma_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
    lzma_state *state = (lzma_state *)malloc(sizeof(lzma_state));
    *stat = (void *)state;
    memset(state, 0, sizeof(lzma_state));
    lzma_stream strm = LZMA_STREAM_INIT;
    state->preset = 6;
    state->type = CRC32;
    state->strm = strm;
    state->seq = seq;
    state->is_mt = false;

    while (param) {
        char* next = strchr(param, ':');
        if (next) {
            *next++ = 0;
        }

        size_t length = strlen(param);
        if (!strcmp(param, "help")) {
            FPLOG(INFO, "%s", lzma_help);
        } else if (!strcmp(param, "z")) {
            state->mode = COMPRESS;
        } else if (!strcmp(param, "d")) {
            state->mode = DECOMPRESS;
        } else if (!strcmp(param, "mt")) {
            state->is_mt = true;
        } else if (!strcmp(param, "bench")) {
            state->do_bench = true;
        } else if (!strcmp(param, "test")) {
            state->mode = TEST;
        } else if (length == 8 && !memcmp(param, "preset=", 7)){
            state->preset = param[7] - '0';

            if (state->preset < 0 || state->preset > 9) {
                FPLOG(FATAL, "plugin doesn't understand encoding preset %d\n", state->preset);
                return 1;
            }
        } else if (length > 6 && !memcmp(param, "check=", 6)) {
            state->type = get_check_type(param + 6);

            if (state->type == UNDEFINED) {
                FPLOG(FATAL, "plugin doesn't understand integrity check type!\n");
                return 1;
            }
        } else {
            FPLOG(FATAL, "plugin doesn't understand param %s\n", param);
            return 1;
        }
        param = next;
    }
    return 0;
}

int lzma_plug_release(void **stat)
{
    if (!stat || !*stat)
        return -1;

    lzma_state *state = (lzma_state *)*stat;
    free(state->output);

    free(*stat);
    return 0;
}

int lzma_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
          unsigned int totslack_pre, unsigned int totslack_post,
	      const fstate_t *fst, void **stat)
{
    lzma_state *state = (lzma_state*)*stat;
    state->opts = opt;

    if (state->mode == TEST && strcmp(opt->iname + strlen(opt->iname) - 2, "xz") != 0) {
        FPLOG(FATAL, "integrity check can be provided only for xz archives!\n");
        return -1;
    }

    if (state->mode == AUTO) {
        if (!strcmp(opt->iname + strlen(opt->iname) - 2, "xz"))
            state->mode = DECOMPRESS;
        else if (!strcmp(opt->oname + strlen(opt->oname) - 2, "xz"))
            state->mode = COMPRESS;
        else {
            FPLOG(FATAL, "can't determine compression/decompression from filenames (and not set)!\n");
            return -1;
        }
    }

    if (init_lzma_stream(state) != LZMA_OK) {
        FPLOG(FATAL, "failed to initialize lzma library!");
        return -1;
    }

    lzma_memlimit_set(&(state->strm), lzma_physmem() / 4);
    if (state->file_size == 0) {
        struct stat st;
        fstat(fst->ides, &st);
        state->file_size = st.st_size;
    }
    return 0;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

void handle_error(lzma_state *state, const char *message) {
    FPLOG(FATAL, message);

    lzma_end(&(state->strm));
    free(state);

    exit(-1);
}

size_t read_bytes(uint8_t *input_buf, unsigned char *input, size_t len, size_t start_pos) {
    size_t result_len = len < CHUNK_SIZE - start_pos ? len : CHUNK_SIZE - start_pos;
    // FPLOG(INFO, "result_len=%d, len=%d\n", result_len, len);
    memcpy(input_buf + start_pos, input, result_len);
    return result_len;
}

void write_bytes(lzma_state *state, size_t start_pos)
{
    if (state->buf_len - CHUNK_SIZE - 1 < start_pos) {
        state->buf_len *= 2;
        state->output = (unsigned char *)realloc(state->output, state->buf_len);
    }

    memcpy(state->output + start_pos, state->output_bf, CHUNK_SIZE);
}

void increase_memlimit(lzma_state *state) {
    uint64_t curr_memlimit = lzma_memlimit_get(&(state->strm));
    uint64_t max_memlimit = lzma_physmem();

    if (curr_memlimit == max_memlimit / 4) {
        lzma_memlimit_set(&(state->strm), max_memlimit / 2);
    } else if (curr_memlimit == max_memlimit / 2) {
        lzma_memlimit_set(&(state->strm), max_memlimit);
    } else {
        handle_error(state, "lzma plugin exceeded memory limit!\n");
    }
}

unsigned char* lzma_algo(unsigned char *bf, lzma_state *state, int eof, fstate_t *fst, int *towr)
{
    size_t bf_len = state->opts->softbs;
    size_t to_read = *towr > bf_len ? bf_len : *towr;

    if (state->output != NULL) {
        free(state->output);
    }
    state->buf_len = (bf_len > CHUNK_SIZE ? bf_len * 2 : CHUNK_SIZE * 2) + 1;
    state->output = (unsigned char *)malloc(state->buf_len);
    size_t curr_pos = 0;

    if (state->readed == state->file_size) {
        state->is_finished = true;
    }

    if (!eof) {
        while (!state->is_finished) {
            memset(state->input_bf, CHUNK_SIZE, 0);
            size_t readed = read_bytes(state->input_bf, bf, to_read, state->pos);
            state->readed += readed;

            if ((state->pos == 0 && readed < CHUNK_SIZE) || state->readed == state->file_size) {
                state->is_finished = true;
            }
            state->pos = 0;

            if (state->is_finished && state->readed != state->file_size) {
                state->pos = readed;
                break;
            }

            bf = bf + readed;
            to_read = to_read - readed;

            state->strm.next_in = state->input_bf;
            state->strm.avail_in = readed;

            lzma_action action = state->is_finished && state->readed == state->file_size ? LZMA_FINISH : LZMA_RUN;

            int ret_xz = 0;
            do {
                state->strm.next_out = state->output_bf;
                state->strm.avail_out = CHUNK_SIZE;

                ret_xz = lzma_code(&(state->strm), action);

                if (ret_xz != LZMA_OK && ret_xz != LZMA_STREAM_END && ret_xz != LZMA_MEMLIMIT_ERROR) {
                    char message[100] = {0};
                    sprintf(message, "(de)compression failed with code: %d\n", ret_xz);
                    handle_error(state, message);
                } else if (ret_xz == LZMA_MEMLIMIT_ERROR) {
                    increase_memlimit(state);
                } else {
                    write_bytes(state, curr_pos);
                    curr_pos += CHUNK_SIZE - state->strm.avail_out;
                }
            } while (state->strm.avail_out != CHUNK_SIZE && ret_xz != LZMA_STREAM_END);
        }
    } else {
        FPLOG(INFO, "filesize=%d, readed=%d\n", state->file_size, state->readed);
    }

    state->is_finished = false;
    if (state->mode == TEST) {
        *towr = 0;
    } else {
        *towr = curr_pos;
    }
    return state->output;
}

unsigned char* lzma_blk_cb(fstate_t *fst, unsigned char* bf, 
			   int *towr, int eof, int *recall, void **stat)
{
    lzma_state *state = (lzma_state*)*stat;

    unsigned char* ptr = 0;	/* Silence gcc */
    clock_t t1 = 0;
    if (state->do_bench) {
        t1 = clock();
    }

    ptr = lzma_algo(bf, state, eof, fst, towr);

    if (state->do_bench) {
        state->cpu += clock() - t1;
    }
    return ptr;
}

int lzma_close(loff_t ooff, void **stat)
{
    lzma_state *state = (lzma_state *)*stat;
    /* Only output if it took us more than 0.05s, otherwise it's completely meaningless */
    if (state->do_bench && state->cpu / (CLOCKS_PER_SEC / 20) > 0) {
        FPLOG(INFO, "%.2fs CPU time\n", (double)state->cpu / CLOCKS_PER_SEC);
    }

    lzma_end(&(state->strm));
    return 0;
}

ddr_plugin_t ddr_plug = {
    .name = "lzma",
    .init_callback  = lzma_plug_init,
    .open_callback  = lzma_open,
    .block_callback = lzma_blk_cb,
    .close_callback = lzma_close,
    .release_callback = lzma_plug_release,
};
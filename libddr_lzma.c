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
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <lzma.h>

#define CHUNK_SIZE 4096

/* fwd decl */
extern ddr_plugin_t ddr_plug;

enum compmode {
    AUTO=0,
    COMPRESS,
    DECOMPRESS
};

typedef struct _lzma_state {
    enum compmode mode;
    unsigned char *output;
    size_t file_size;
    size_t buf_len;
    size_t curr_pos;
    lzma_stream strm;
    const opt_t *opts;
    bool do_bench;
    bool is_finished;
    clock_t cpu;
    int seq;
} lzma_state;

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

const char* null_help = "LZMA plugin which is doing compression/decompression for xz archives.\n";

lzma_ret init_lzma_stream(lzma_state* state) {
    // disable limits, no check done for uncompressed data
    return state->mode == COMPRESS ? lzma_easy_encoder(&(state->strm), 6, LZMA_CHECK_NONE) :
            lzma_auto_decoder(&(state->strm), UINT64_MAX, LZMA_CONCATENATED | LZMA_TELL_UNSUPPORTED_CHECK);
}

int lzma_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
    lzma_state *state = (lzma_state *)malloc(sizeof(lzma_state));
    *stat = (void *)state;
    memset(state, 0, sizeof(lzma_state));
    lzma_stream strm = LZMA_STREAM_INIT;
    state->strm = strm;
    state->seq = seq;

    while (param) {
        char* next = strchr(param, ':');
        if (next) {
            *next++ = 0;
        }

        if (!strcmp(param, "help")) {
            FPLOG(INFO, "%s", null_help);
        } else if (!strcmp(param, "z")) {
            state->mode = COMPRESS;
        } else if (!strcmp(param, "d")) {
            state->mode = DECOMPRESS;
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
    return 0;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

size_t read_bytes(uint8_t *input_buf, unsigned char *input, size_t len) {
    size_t result_len = len < CHUNK_SIZE ? len : CHUNK_SIZE;
    FPLOG(INFO, "result_len=%d, len=%d\n", result_len, len);
    memcpy(input_buf, input, result_len);

    return result_len;
}

void write_bytes(uint8_t *output_buf, lzma_state *state, size_t start_pos)
{
    if (state->buf_len - CHUNK_SIZE - 1 < start_pos) {
        state->buf_len *= 2;
        state->output = (unsigned char *)realloc(state->output, state->buf_len);
    }

    memcpy(state->output + start_pos, output_buf, CHUNK_SIZE);
}

unsigned char* lzma_algo(unsigned char *bf, lzma_state *state, int eof, fstate_t *fst, int *towr)
{
    if (state->file_size == 0) {
        struct stat st;
        fstat(fst->ides, &st);
        state->file_size = st.st_size;
    }
    size_t bf_len = malloc_usable_size(bf);
    size_t real_len = (state->file_size - state->curr_pos) > bf_len ?
            bf_len : (state->file_size - state->curr_pos);

    if (state->output == NULL) {
        state->buf_len = (bf_len > CHUNK_SIZE ? bf_len * 2 : CHUNK_SIZE * 2) + 1;
        state->output = (unsigned char *)malloc(state->buf_len);
        state->curr_pos = 0;
    }
    size_t curr_pos = state->curr_pos;

    uint8_t input_buf[CHUNK_SIZE + 1] = {0};
    uint8_t output_buf[CHUNK_SIZE + 1] = {0};

    if (!eof) {
        while (!state->is_finished) {
            memset(input_buf, CHUNK_SIZE, 0);
            size_t readed = read_bytes(input_buf, bf, real_len);
            if (readed < CHUNK_SIZE) {
                state->is_finished = true;
            }

            bf = bf + readed;
            real_len = real_len - readed;

            state->strm.next_in = input_buf;
            state->strm.avail_in = readed;

            lzma_action action = state->is_finished ? LZMA_FINISH : LZMA_RUN;

            do {
                state->strm.next_out = output_buf;
                state->strm.avail_out = CHUNK_SIZE;

                int ret_xz = lzma_code(&(state->strm), action);

                if (ret_xz != LZMA_OK && ret_xz != LZMA_STREAM_END) {
                    exit(-1);
                } else {
                    write_bytes(output_buf, state, state->curr_pos);
                    state->curr_pos += CHUNK_SIZE - state->strm.avail_out;
                }
            } while (state->strm.avail_out == 0);
        }
    }

    *towr = state->curr_pos - curr_pos;
    return state->output + curr_pos;
}

unsigned char* lzma_compress(fstate_t *fst, unsigned char *bf, 
			    int *towr, int eof, int *recall, lzma_state *state)
{
    return lzma_algo(bf, state, eof, fst, towr);
}

unsigned char* lzma_decompress(fstate_t *fst, unsigned char* bf, int *towr,
			      int eof, int *recall, lzma_state *state)
{
    return lzma_algo(bf, state, eof, fst, towr);
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

    if (state->mode == COMPRESS) 
        ptr = lzma_compress(fst, bf, towr, eof, recall, state);
    else {
        ptr = lzma_decompress(fst, bf, towr, eof, recall, state);
    }

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
    .needs_align = 0,
    .handles_sparse = 1,
    .init_callback  = lzma_plug_init,
    .open_callback  = lzma_open,
    .block_callback = lzma_blk_cb,
    .close_callback = lzma_close,
    .release_callback = lzma_plug_release,
};
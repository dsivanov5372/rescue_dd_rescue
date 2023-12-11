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
    uint8_t input_bf[CHUNK_SIZE + 1];
    uint8_t output_bf[CHUNK_SIZE + 1];
    size_t pos;
    enum compmode mode;
    unsigned char *output;
    size_t file_size;
    size_t buf_len;
    size_t readed;
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
        } else if (!strcmp(param, "bench")) {
            state->do_bench = true;
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

unsigned char* lzma_algo(unsigned char *bf, lzma_state *state, int eof, fstate_t *fst, int *towr)
{
    size_t bf_len = malloc_usable_size(bf) - CHUNK_SIZE;
    size_t to_read = (state->file_size - state->readed) > bf_len ?
            bf_len : (state->file_size - state->readed);

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

            do {
                state->strm.next_out = state->output_bf;
                state->strm.avail_out = CHUNK_SIZE;

                int ret_xz = lzma_code(&(state->strm), action);

                if (ret_xz != LZMA_OK && ret_xz != LZMA_STREAM_END) {
                    exit(-1);
                } else {
                    write_bytes(state, curr_pos);
                    curr_pos += CHUNK_SIZE - state->strm.avail_out;
                }
            } while (state->strm.avail_out == 0);
        }
    } else {
        FPLOG(INFO, "filesize=%d, readed=%d\n", state->file_size, state->readed);
    }

    state->is_finished = false;
    *towr = curr_pos;
    return state->output;
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
    .init_callback  = lzma_plug_init,
    .open_callback  = lzma_open,
    .block_callback = lzma_blk_cb,
    .close_callback = lzma_close,
    .release_callback = lzma_plug_release,
};
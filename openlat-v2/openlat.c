#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "openlat.h"
#include "openlat.skel.h"


static struct env {
  __u64 min_us;
  __u64 min_event_us;
  pid_t pid;
  char comm[TASK_COMM_LEN];
  bool verbose;
  time_t duration;
  bool per_process;
  bool milliseconds;
} env = {
  .duration = 99999999,
  .min_event_us = 1000,
};


static volatile bool exiting = false;


const char* argp_program_version = "openlat 2.0";
const char argp_program_doc[] =
    "Summarize open() latency as a per-process log2 histogram.\n"
    "\n"
    "Runs until the duration elapses or Ctrl-C, then prints one final summary.\n"
    "\n"
    "USAGE: openlat [--help] [-m MIN_MS] [-p PID] [-c COMM] [duration]\n"
    "\n"
    "EXAMPLES:\n"
    "   openlat            # run until Ctrl-C, then print the histogram\n"
    "   openlat 5          # run for 5 seconds, then print the histogram\n"
    "   openlat -m 1       # only opens slower than 1 ms\n"
    "   openlat -m 0.1     # only opens slower than 100 us\n"
    "   openlat -p 8585    # trace PID 8585 only\n"
    "   openlat -c nginx   # trace processes named nginx only\n"
    "   openlat -s 5       # live event for each open slower than 5 ms\n";

static const struct argp_option opts[] = {
  {"min-us", 'm', "MIN_US", 0, "Only count opens slower than this (ms) in the histogram"},
  {"slower", 's', "MS", 0, "Emit a live event for each open slower than this (ms, default 1)"},
  {"pid", 'p', "PID", 0, "Trace this PID only"},
  {"per-process", 'P', NULL, 0, "Per-process histograms"},
  {"milliseconds", 'M', NULL, 0, "Bucket the histogram in ms instead of us"},
  {"comm", 'c', "COMM", 0, "Trace these commands only"},
  {"verbose", 'v', NULL, 0, "Verbose debug output"},
  {NULL, 'h', NULL, OPTION_HIDDEN, "Print full help"},
  {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
  static int pos_args;

  switch (key) {
    case 'h':
      argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
      break;
    case 'v':
      env.verbose = true;
      break;
    case 'P':
      env.per_process = true;
      break;
    case 'M':
      env.milliseconds = true;
      break;
    case 'p':
      errno = 0;
      env.pid = strtol(arg, NULL, 10);
      if (errno) {
        fprintf(stderr, "invalid PID: %s\n", arg);
        argp_usage(state);
      }
      break;
    case 'c':
      strncpy(env.comm, arg, TASK_COMM_LEN - 1);
      env.comm[TASK_COMM_LEN - 1] = '\0';
      break;
    case 'm':
      errno = 0;
      env.min_us = strtod(arg, NULL) * 1000;
      if (errno || env.min_us <= 0) {
        fprintf(stderr, "Invalid delay (in us): %s\n", arg);
        argp_usage(state);
      }
      break;
    case 's':
      errno = 0;
      env.min_event_us = strtod(arg, NULL) * 1000;
      if (errno || env.min_event_us <= 0) {
        fprintf(stderr, "Invalid slow threshold (ms): %s\n", arg);
        argp_usage(state);
      }
      break;
    case ARGP_KEY_ARG:
      errno = 0;
      if (pos_args == 0) {
        env.duration = strtol(arg, NULL, 10);
        if (errno) {
          fprintf(stderr, "invalid internal\n");
          argp_usage(state);
        }
      } else {
        fprintf(stderr, "unrecognized positional argument: %s\n", arg);
        argp_usage(state);
      }
      pos_args++;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  	}
  	return 0;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
  if (level == LIBBPF_DEBUG && !env.verbose) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}


static void sig_handler(int sig)
{
  exiting = true;
}


static int get_summary(struct bpf_map *hists) {
  int err;
  __u32 cur_key = -1;
  __u32 next_key;
  struct hist hist;
  int fd = bpf_map__fd(hists);

  printf("\n=========================== open() latency summary ===========================\n");
  while(bpf_map_get_next_key(fd, &cur_key, &next_key) == 0) {
    err = bpf_map_lookup_elem(fd, &next_key, &hist);
    if (err < 0) {
      fprintf(stderr, "Failed to lookup hists: %d\n", err);
			return -1;
    }

    int max = 0;
    for (int i = 0; i < MAX_SLOTS; i++) {
      if (max < hist.slots[i]) {
        max = hist.slots[i];
      }
    }

    if (max == 0) {
      cur_key = next_key;
      continue;
    }

    if (env.per_process) {
      printf("\nPID %d (%s)\n", next_key, hist.comm);
    }

    printf("%10s    %-10s : %-8s %s\n", "",
           env.milliseconds ? "msecs" : "usecs", "count", "distribution");
    for (int i = 0; i < MAX_SLOTS; i++) {
      if (hist.slots[i] == 0) {
        continue;
      }

      int low = 1 << i;
      int high = (1 << (i + 1)) - 1;
      int stars = hist.slots[i] * MAX_STARS / max;

      printf("%10d -> %-10d : %-8d |", low, high, hist.slots[i]);

      for (int j = 0; j < stars; j++) {
        putchar('*');
      }

      for (int j = stars; j < MAX_STARS; j++) {
        putchar(' ');
      }

      printf("|\n");
    }
    putchar('\n');

    cur_key = next_key;
  }

	return 0;
}


static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  printf("%-7d %-16s %-10llu %s\n", e->pid, e->comm, e->delta_us, e->filename);
  return 0;
}


int main(int argc, char** argv) {
  static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
  };
  struct openlat_bpf *skel;
  struct ring_buffer *rb = NULL;
  int err;

  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err) {
    return err;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  libbpf_set_print(libbpf_print_fn);

  skel = openlat_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open Openlat BPF skeleton\n");
    return 1;
  }
  skel->rodata->per_process = env.per_process;
  skel->rodata->target_pid = env.pid;
  skel->rodata->target_min_us = env.min_us;
  skel->rodata->min_event_us = env.min_event_us;
  skel->rodata->milliseconds = env.milliseconds;
  strncpy(skel->rodata->target_comm,
          env.comm,
          sizeof(skel->rodata->target_comm) - 1);
  skel->rodata->target_comm[sizeof(skel->rodata->target_comm) - 1] = '\0';

  err = openlat_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load Openlat BPF skeleton\n");
    goto tschuss;
  }

  err = openlat_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach Openlat BPF skeleton\n");
    goto tschuss;
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.ring_buff), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto tschuss;
  }

  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  printf("%-7s %-16s %-10s %s\n", "PID", "COMM", "DELTA(us)", "FILENAME");
  while (!exiting) {
    err = ring_buffer__poll(rb, 100);
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
    if (elapsed >= env.duration) break;
  }
  printf("\n");
  printf("\n");
  get_summary(skel->maps.hists);

tschuss:
  ring_buffer__free(rb);
  openlat_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}

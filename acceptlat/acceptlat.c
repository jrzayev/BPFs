#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "acceptlat.h"
#include "acceptlat.skel.h"


static struct env {
  long port;
  long pid;
  long min_us;
} env;


const char argp_program_doc[] =
"acceptlat: time spent by accepted TCP connections waiting in the accept queue.\n"
"\n"
"USAGE: ./acceptlat [-P LPORT] [-p PID] [-m MIN-US]\n";


static const struct argp_option opts[] = {
  { "port", 'P', "PORT", 0, "Filter by local (server) port" },
  { "pid", 'p', "PID", 0, "Filter by accepting process PID" },
  { "min", 'm', "MIN-US", 0, "Only show waits longer than this, us" },
  {},
};


static volatile bool exiting = false;


static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
  switch (key) {
    case 'P':
      errno = 0;
      env.port = strtol(arg, NULL, 10);
      if (errno || env.port <= 0 || env.port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", arg);
        argp_usage(state);
      }
      break;
    case 'p':
      errno = 0;
      env.pid = strtol(arg, NULL, 10);
      if (errno || env.pid <= 0) {
        fprintf(stderr, "Invalid pid: %s\n", arg);
        argp_usage(state);
      }
      break;
    case 'm':
      errno = 0;
      env.min_us = strtol(arg, NULL, 10);
      if (errno || env.min_us < 0) {
        fprintf(stderr, "Invalid min latency: %s\n", arg);
        argp_usage(state);
      }
      break;
    case ARGP_KEY_ARG:
      argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
  .options = opts,
  .parser = parse_arg,
  .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
  va_list args)
{
  // if you want more clean output just uncomment following 2 lines
	// if (level == LIBBPF_DEBUG)
	// 		return 0;
  return vfprintf(stderr, format, args);
}


static void sig_handler(int sig)
{
  exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
  const struct event *e = data;
  char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
  char ts[32];
  struct tm *tm;
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (e->af == AF_INET) {
    inet_ntop(AF_INET, &e->saddr_v4, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr_v4, daddr, sizeof(daddr));
  } else {
    inet_ntop(AF_INET6, e->saddr_v6, saddr, sizeof(saddr));
    inet_ntop(AF_INET6, e->daddr_v6, daddr, sizeof(daddr));
  }

  printf("%-8s %-16s %-7u %-20s %-6u %-20s %-6u %.3f\n",
         ts, e->comm, e->tgid, saddr, e->sport, daddr, e->dport,
         e->delta_us / 1000.0);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
  fprintf(stderr, "lost %llu events on CPU %d\n", cnt, cpu);
}

int main(int argc, char **argv)
{
  struct perf_buffer *pb = NULL;
  struct acceptlat_bpf *skel;
  int err;

  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = acceptlat_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  skel->rodata->target_sport = env.port;
  skel->rodata->target_min_us = env.min_us;
  skel->rodata->target_tgid = env.pid;

  err = acceptlat_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton\n");
    goto bye;
  }

  err = acceptlat_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto bye;
  }

  pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                        handle_event, handle_lost, NULL, NULL);
  if (!pb) {
    err = -1;
    fprintf(stderr, "Failed to create perf buffer\n");
    goto bye;
  }

  printf("%-8s %-16s %-7s %-20s %-6s %-20s %-6s %s\n",
         "TIME", "COMM", "PID", "LADDR", "LPORT", "RADDR", "RPORT", "LAT(ms)");
  while (!exiting) {
    err = perf_buffer__poll(pb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "Error polling perf buffer: %d\n", err);
      break;
    }
  }

bye:
  perf_buffer__free(pb);
  acceptlat_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}

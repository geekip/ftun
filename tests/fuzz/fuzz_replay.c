#define _GNU_SOURCE 1

#include "fuzz_common.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* 没有 libFuzzer 时的回放驱动：把语料目录里的文件和目标内置种子逐个送进入口，
 * 再按固定随机序列做确定性变异（翻转位、改字节、插入、删除、截断、复制片段、
 * 拼接其他种子）。迭代次数由 FTUN_FUZZ_ITERATIONS 指定（默认 20000），随机种子由
 * FTUN_FUZZ_SEED 指定。用法：回放程序 [--dump-seeds 目录] [语料目录或文件...]。
 * 这是冒烟，不替代 libFuzzer 的覆盖率引导。 */

#define MAX_SEEDS 512u
#define MAX_SEED_BYTES (256u * 1024u)
#define MAX_INPUT_BYTES (MAX_SEED_BYTES + 4096u)
#define PREFIX_LIMIT 512u

typedef struct {
  uint8_t *data;
  size_t size;
} seed_t;

static seed_t seeds[MAX_SEEDS];
static size_t seed_count;
static uint32_t random_state = UINT32_C(0x46544e31);

extern int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));
extern void ftun_fuzz_seeds(ftun_fuzz_seed_fn add) __attribute__((weak));

static uint32_t next_random(void)
{
  uint32_t value = random_state;
  value ^= value << 13u;
  value ^= value >> 17u;
  value ^= value << 5u;
  random_state = value;
  return value;
}

static void add_seed(const uint8_t *data, size_t size)
{
  uint8_t *copy;
  if (seed_count >= MAX_SEEDS || size > MAX_SEED_BYTES) return;
  copy = (uint8_t *)malloc(size == 0u ? 1u : size);
  if (copy == NULL) abort();
  if (size != 0u) memcpy(copy, data, size);
  seeds[seed_count].data = copy;
  seeds[seed_count].size = size;
  seed_count++;
}

static void add_file(const char *path)
{
  struct stat info;
  uint8_t *buffer;
  ssize_t count;
  int descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) return;
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_size < 0 || (size_t)info.st_size > MAX_SEED_BYTES) {
    (void)close(descriptor);
    return;
  }
  buffer = (uint8_t *)malloc((size_t)info.st_size + 1u);
  if (buffer == NULL) abort();
  count = read(descriptor, buffer, (size_t)info.st_size);
  (void)close(descriptor);
  if (count == info.st_size) add_seed(buffer, (size_t)count);
  free(buffer);
}

static void add_path(const char *path)
{
  struct stat info;
  DIR *directory;
  struct dirent *entry;
  if (stat(path, &info) != 0) return;
  if (S_ISREG(info.st_mode)) {
    add_file(path);
    return;
  }
  directory = opendir(path);
  if (directory == NULL) return;
  while ((entry = readdir(directory)) != NULL) {
    char child[4096];
    if (entry->d_name[0] == '.') continue;
    if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) <
        (int)sizeof(child)) add_file(child);
  }
  (void)closedir(directory);
}

static void run(const uint8_t *data, size_t size)
{
  /* 恰好 size 字节的堆块，ASan 能发现任何越界读。 */
  uint8_t *exact = (uint8_t *)malloc(size == 0u ? 1u : size);
  if (exact == NULL) abort();
  if (size != 0u) memcpy(exact, data, size);
  (void)LLVMFuzzerTestOneInput(exact, size);
  free(exact);
}

static size_t mutate(const seed_t *seed, uint8_t *output)
{
  size_t size = seed->size;
  unsigned int rounds = 1u + next_random() % 4u;
  if (size != 0u) memcpy(output, seed->data, size);
  while (rounds-- != 0u) {
    uint32_t kind = next_random() % 8u;
    size_t position = size == 0u ? 0u : next_random() % size;
    switch (kind) {
    case 0: if (size != 0u) output[position] ^= (uint8_t)(1u << (next_random() & 7u)); break;
    case 1: if (size != 0u) output[position] = (uint8_t)next_random(); break;
    case 2:
      if (size < MAX_SEED_BYTES) {
        memmove(output + position + 1u, output + position, size - position);
        output[position] = (uint8_t)next_random();
        size++;
      }
      break;
    case 3:
      if (size != 0u) {
        memmove(output + position, output + position + 1u, size - position - 1u);
        size--;
      }
      break;
    case 4: size = position; break;
    case 5:
      if (size != 0u) {
        size_t length = 1u + next_random() % (size - position);
        if (size + length <= MAX_SEED_BYTES) {
          memmove(output + position + length, output + position, size - position);
          memcpy(output + position, output + position + length, length);
          size += length;
        }
      }
      break;
    case 6:
      if (seed_count > 1u) {
        const seed_t *other = &seeds[next_random() % seed_count];
        size_t length = other->size == 0u ? 0u : 1u + next_random() % other->size;
        if (position + length <= MAX_SEED_BYTES) {
          memcpy(output + position, other->data, length);
          if (position + length > size) size = position + length;
        }
      }
      break;
    default:
      if (size >= 4u) {
        /* 把一个 4 字节整数改成边界值：长度/计数字段最容易出问题。 */
        static const uint32_t edges[] = {0u, 1u, 0x7fu, 0xffu, 0xffffu, 0x7fffffffu, 0xffffffffu};
        uint32_t edge = edges[next_random() % (sizeof(edges) / sizeof(edges[0]))];
        position = next_random() % (size - 3u);
        memcpy(output + position, &edge, sizeof(edge));
      }
      break;
    }
  }
  return size;
}

int main(int argc, char **argv)
{
  const char *dump = NULL;
  const char *text;
  unsigned long iterations = 20000ul;
  unsigned long iteration;
  size_t index;
  int arg = 1;
  uint8_t *buffer;
  if (LLVMFuzzerInitialize != NULL) (void)LLVMFuzzerInitialize(&argc, &argv);
  if (ftun_fuzz_seeds != NULL) ftun_fuzz_seeds(add_seed);
  if (arg + 1 < argc && strcmp(argv[arg], "--dump-seeds") == 0) {
    dump = argv[arg + 1];
    arg += 2;
  }
  for (; arg < argc; arg++) add_path(argv[arg]);
  if (dump != NULL) {
    (void)mkdir(dump, 0755);
    for (index = 0u; index < seed_count; index++) {
      char path[4096];
      FILE *file;
      (void)snprintf(path, sizeof(path), "%s/seed-%03zu", dump, index);
      file = fopen(path, "wb");
      if (file == NULL) return 1;
      if (seeds[index].size != 0u) (void)fwrite(seeds[index].data, 1u, seeds[index].size, file);
      if (fclose(file) != 0) return 1;
    }
    printf("wrote %zu seeds to %s\n", seed_count, dump);
    return 0;
  }
  text = getenv("FTUN_FUZZ_ITERATIONS");
  if (text != NULL) iterations = strtoul(text, NULL, 10);
  text = getenv("FTUN_FUZZ_SEED");
  if (text != NULL) random_state ^= (uint32_t)strtoul(text, NULL, 10);
  if (random_state == 0u) random_state = 1u;
  if (seed_count == 0u) add_seed((const uint8_t *)"", 0u);
  buffer = (uint8_t *)malloc(MAX_INPUT_BYTES);
  if (buffer == NULL) return 1;
  /* 种子原样，以及较短种子的全部前缀（截断是协议解析最常见的错误来源）。 */
  for (index = 0u; index < seed_count; index++) {
    size_t prefix;
    run(seeds[index].data, seeds[index].size);
    for (prefix = 0u; prefix < seeds[index].size && prefix < PREFIX_LIMIT; prefix++) {
      run(seeds[index].data, prefix);
    }
  }
  for (iteration = 0ul; iteration < iterations; iteration++) {
    size_t size = mutate(&seeds[next_random() % seed_count], buffer);
    run(buffer, size);
  }
  free(buffer);
  printf("fuzz replay: %zu seeds, %lu mutations, no failures\n", seed_count, iterations);
  return 0;
}

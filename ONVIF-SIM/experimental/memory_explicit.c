/*
 * EXPLICIT MEMORY MANAGEMENT - Page-Aligned Buffers
 * 
 * This shows memory allocation at 4KB page granularity (no malloc abstraction).
 * 
 * GOAL: Understand memory pages, alignment, and kernel memory management.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * KEY INSIGHT: Memory Pages
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Your process's memory is organized in 4KB pages:
 *   - Virtual address space divided into pages
 *   - Each page = 4096 bytes (4KB)
 *   - Page-aligned addresses divisible by 4096
 *   - Kernel maps virtual → physical pages
 * 
 * Why care?
 *   - Network DMA requires page-aligned buffers
 *   - Zero-copy (splice, sendfile) works on pages
 *   - CPU cache lines are 64 bytes (sub-page granularity)
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define _GNU_SOURCE
#include <sys/mman.h>     /* mmap, munmap, madvise */
#include <sys/syscall.h>  /* SYS_mmap, etc. */
#include <unistd.h>       /* syscall, getpagesize */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/* Page size constant (4KB on most systems, but check runtime) */
#define PAGE_SIZE 4096

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * THEORY → CODE: Memory Pages
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * malloc() vs mmap():
 * 
 * malloc():
 *   - libc function (userspace allocator)
 *   - Uses brk() or mmap() internally
 *   - May not be page-aligned
 *   - Cannot give hints to kernel
 *   - Abstraction hides page boundaries
 * 
 * mmap():
 *   - Direct syscall to kernel
 *   - Always returns page-aligned address
 *   - You control page allocation
 *   - Can advise kernel (madvise)
 *   - Explicit page management
 * 
 * Example:
 *   void *ptr = malloc(100);        // Might be at 0x55f3a8e4c2a0 (not aligned)
 *   void *ptr = mmap(..., 4096);    // Will be at 0x7f3b4c000000 (page-aligned)
 */

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  EXPLICIT MEMORY MANAGEMENT - Page Alignment\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 1: CHECK PAGE SIZE                                        │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Page size is architecture-dependent:
     *   - x86/x64: 4KB (4096 bytes)
     *   - ARM: 4KB or 64KB
     *   - Some systems: 8KB, 16KB
     * 
     * Always check at runtime!
     */
    
    long page_size = sysconf(_SC_PAGESIZE);
    printf("[SYSTEM]  Page size: %ld bytes (%ld KB)\n", page_size, page_size / 1024);
    printf("[SYSTEM]  All memory allocations happen in page multiples\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 2: ALLOCATE PAGE-ALIGNED MEMORY (mmap)                    │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * mmap() creates anonymous mapping (memory not backed by file).
     * 
     * Parameters:
     *   addr:   NULL (let kernel choose address)
     *   length: Size in bytes (rounded up to pages)
     *   prot:   PROT_READ | PROT_WRITE (readable + writable)
     *   flags:  MAP_PRIVATE | MAP_ANONYMOUS (private, no file)
     *   fd:     -1 (no file descriptor)
     *   offset: 0 (no file offset)
     * 
     * What happens in kernel:
     *   1. Find free virtual address space
     *   2. Create VMA (virtual memory area) struct
     *   3. Don't allocate physical pages yet (lazy allocation!)
     *   4. Return virtual address
     *   5. On first access → page fault → allocate physical page
     */
    
    size_t buffer_size = 4096;  /* One page */
    
    void *buffer = mmap(NULL,                      /* Let kernel choose address */
                       buffer_size,                /* Size: 4KB */
                       PROT_READ | PROT_WRITE,     /* Readable + writable */
                       MAP_PRIVATE | MAP_ANONYMOUS,/* Private, anonymous */
                       -1,                         /* No file descriptor */
                       0);                         /* No offset */
    
    if (buffer == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    
    printf("[SYSCALL] mmap() returned address: %p\n", buffer);
    printf("[CHECK]   Address %% 4096 = %ld (should be 0 = page-aligned)\n", 
           (uintptr_t)buffer % 4096);
    printf("[KERNEL]  VMA created, physical pages NOT yet allocated\n");
    printf("[KERNEL]  Physical allocation happens on first write (lazy)\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ THEORY: Page Alignment Benefits                                │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Why page-aligned buffers matter for networking:
     * 
     * 1. DMA (Direct Memory Access):
     *    - NIC can directly read/write page-aligned buffers
     *    - Avoids CPU copying
     *    - Requires physical contiguity (or IOMMU)
     * 
     * 2. Zero-copy operations:
     *    - sendfile(): kernel can splice pages
     *    - splice(): move pages between fd without copying
     *    - MSG_ZEROCOPY: NIC reads directly from userspace pages
     * 
     * 3. Cache efficiency:
     *    - CPU cache works on cache lines (64 bytes)
     *    - Page-aligned = no false sharing
     *    - Better prefetch behavior
     * 
     * 4. Huge pages (optional):
     *    - 2MB or 1GB pages (instead of 4KB)
     *    - Reduces TLB misses
     *    - MAP_HUGETLB flag
     */

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 3: WRITE TO BUFFER (trigger physical allocation)          │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Writing triggers page fault:
     *   1. CPU tries to access virtual address
     *   2. Page table lookup fails (no physical page)
     *   3. CPU raises page fault exception
     *   4. Kernel handles page fault:
     *      - Allocates physical page (4KB)
     *      - Updates page table entry
     *      - Maps virtual → physical
     *   5. CPU retries instruction (now succeeds)
     */
    
    printf("[ACTION]  Writing to buffer...\n");
    memset(buffer, 0xAA, buffer_size);  /* Write pattern 0xAA */
    printf("[KERNEL]  Page fault occurred (first write)\n");
    printf("[KERNEL]  Physical page allocated\n");
    printf("[KERNEL]  Page table updated (virtual → physical mapping)\n");
    printf("[MEMORY]  Buffer now backed by real physical memory\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 4: ADVISE KERNEL (madvise)                                │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * madvise() gives hints to kernel about memory access patterns.
     * 
     * Options:
     *   MADV_NORMAL:     No special behavior
     *   MADV_RANDOM:     Expect random access (disable readahead)
     *   MADV_SEQUENTIAL: Expect sequential access (aggressive readahead)
     *   MADV_WILLNEED:   Expect access soon (prefetch)
     *   MADV_DONTNEED:   Don't need anymore (discard pages)
     * 
     * For networking buffers:
     *   - MADV_WILLNEED before recv() (prefetch)
     *   - MADV_DONTNEED after send() (free memory)
     */
    
    int madvise_ret = madvise(buffer, buffer_size, MADV_WILLNEED);
    if (madvise_ret < 0) {
        perror("madvise failed");
    } else {
        printf("[SYSCALL] madvise(MADV_WILLNEED) completed\n");
        printf("[KERNEL]  Kernel will prefetch pages\n");
        printf("[HINT]    Useful before network recv() operations\n\n");
    }

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ THEORY: Cache Line Alignment                                   │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * Modern CPUs have cache hierarchy:
     *   L1 cache: ~32KB, 64-byte cache lines
     *   L2 cache: ~256KB, 64-byte cache lines
     *   L3 cache: ~8MB, 64-byte cache lines
     * 
     * Cache line = smallest unit of cache coherency
     * 
     * Problem: False sharing
     *   Thread 1 writes to byte 0
     *   Thread 2 writes to byte 63
     *   → Both on same cache line → cache ping-pong → slow!
     * 
     * Solution: Align data to cache line boundaries (64 bytes)
     */
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  CACHE LINE ALIGNMENT\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("CPU cache line size: typically 64 bytes\n");
    printf("Buffer address: %p\n", buffer);
    printf("Cache line aligned: %s (addr %% 64 = %ld)\n",
           ((uintptr_t)buffer % 64 == 0) ? "YES" : "NO",
           (uintptr_t)buffer % 64);
    printf("\nFor multi-threaded networking:\n");
    printf("  - Align per-thread buffers to 64-byte boundaries\n");
    printf("  - Avoids false sharing\n");
    printf("  - Better cache locality\n\n");

    /*
     * ┌────────────────────────────────────────────────────────────────┐
     * │ STEP 5: DEALLOCATE (munmap)                                    │
     * └────────────────────────────────────────────────────────────────┘
     * 
     * munmap() releases virtual address space.
     * 
     * What happens:
     *   1. Kernel removes VMA
     *   2. Frees physical pages
     *   3. Flushes TLB (translation lookaside buffer)
     *   4. Virtual address space available for reuse
     */
    
    int munmap_ret = munmap(buffer, buffer_size);
    if (munmap_ret < 0) {
        perror("munmap failed");
        return 1;
    }
    
    printf("[SYSCALL] munmap() completed\n");
    printf("[KERNEL]  VMA removed\n");
    printf("[KERNEL]  Physical pages freed\n");
    printf("[KERNEL]  TLB flushed\n\n");

    /*
     * ═══════════════════════════════════════════════════════════════════
     * COMPARISON: malloc() vs mmap()
     * ═══════════════════════════════════════════════════════════════════
     * 
     * malloc(100):
     *   - Userspace allocator (glibc's ptmalloc2)
     *   - Uses brk() for small allocations
     *   - Uses mmap() for large allocations (>128KB threshold)
     *   - Address may not be page-aligned
     *   - Cannot give kernel hints
     *   - Fast for small allocations (no syscall)
     * 
     * mmap(4096):
     *   - Direct syscall every time
     *   - Always page-aligned
     *   - Can use madvise() for hints
     *   - Can use MAP_HUGETLB for huge pages
     *   - Better control for I/O buffers
     *   - Slower for small allocations (syscall overhead)
     * 
     * For networking:
     *   - Use malloc() for small structs (< 1KB)
     *   - Use mmap() for large buffers (> 4KB)
     *   - Use posix_memalign() for cache line alignment
     */

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  COMPLETE\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    printf("You now understand:\n");
    printf("  ✓ Memory organized in 4KB pages\n");
    printf("  ✓ mmap() returns page-aligned addresses\n");
    printf("  ✓ Lazy allocation (page fault on first access)\n");
    printf("  ✓ madvise() gives kernel hints\n");
    printf("  ✓ Cache lines (64 bytes) matter for performance\n\n");
    printf("For networking buffers:\n");
    printf("  ✓ Use mmap() for large buffers (DMA-friendly)\n");
    printf("  ✓ Align to pages (4KB) and cache lines (64 bytes)\n");
    printf("  ✓ Use madvise() to optimize access patterns\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * COMPILE AND RUN
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Compile:
 *   gcc -o memory_explicit memory_explicit.c -std=c11 -Wall
 * 
 * Run:
 *   ./memory_explicit
 * 
 * Trace syscalls:
 *   strace -e mmap,madvise,munmap ./memory_explicit
 * 
 * Expected strace output:
 *   mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f...
 *   madvise(0x7f..., 4096, MADV_WILLNEED) = 0
 *   munmap(0x7f..., 4096) = 0
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * EXERCISES
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * 1. Allocate 10 pages (40KB), observe alignment
 * 2. Use MAP_HUGETLB to allocate 2MB huge page
 * 3. Measure page fault overhead with getrusage()
 * 4. Implement custom allocator using mmap() + free list
 * 5. Compare malloc() vs mmap() performance for 1KB, 4KB, 1MB
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 */

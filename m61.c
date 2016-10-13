#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <stdbool.h>

struct front_metadata
{
    struct front_metadata* prev; //previous active allocation
    struct front_metadata* next; //next active allocation
    const char* file;
    int line;
    int free_marker;
    size_t size;
    int front_buffer;
};

typedef struct front_metadata front_metadata;

struct counter
{
    long count;
    int line;
    char* file;
    long size;
};

typedef struct counter counter;

#define COUNT 5 // number of counters for heavy hitters
counter counters[COUNT];//declares an array of m counters


static struct m61_statistics *my_stats;
// used to make a linked list between allocations in the metadata itself
static front_metadata* first_alloc = NULL; //global, keeps track of the earliest allocation that is still active
static front_metadata* last_alloc = NULL; //global, keeps track of the most recent allocation that is still active

/*
memory currently looks like
|front_metadata| |actual allocation| |int for write buffer|
*/

struct m61_statistics* initialize(void);
const int front_padding = sizeof(front_metadata);
const int end_padding = sizeof(int);
//put this before the size_t containing the size, use to detect invalid frees.
int allocated;
int freed;
//put this immediately before and after the allocation itself, used to detect wild write
int write_buffer;

struct m61_statistics* initialize()
{
    allocated = rand();
    freed = rand();
    write_buffer = rand();
    my_stats = malloc(sizeof(struct m61_statistics));
    (*my_stats).nactive = 0;
    (*my_stats).active_size = 0;
    (*my_stats).ntotal = 0;
    (*my_stats).total_size = 0;
    (*my_stats).nfail = 0;
    (*my_stats).fail_size = 0;
    (*my_stats).heap_min = NULL;
    (*my_stats).heap_max = NULL;

    //initialize counters to zero (step one of Frequent algorithm)
    for (int i = 0; i < COUNT; i++)
    {
        counters[i].count = 0;
        counters[i].line = -1;
        counters[i].file = NULL;
        counters[i].size = 0;
    }
    return my_stats;
}

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line)
{
    if (my_stats == NULL)
        initialize();
    // track memory usage: use active_size and total_size from the m61_statistics struct
    // the first sizeof(size_t) bytes are metadata that will be used to store the size of this pointer. We need to check that adding on those bytes won't cause integer overflow. If it does, allocation fails.
    if (((size_t) -1) - sz < sizeof(size_t))
    {
        (*my_stats).nfail += 1;
        (*my_stats).fail_size += sz;
        return NULL;
    }
    front_metadata* fm = (front_metadata*) base_malloc(sz + front_padding + end_padding);// dummy ptr which includes metadata
    if (fm == NULL)
    {
        (*my_stats).nfail += 1;
        (*my_stats).fail_size += sz;
        return NULL;
    }
    else
    {
        (*my_stats).nactive += 1;
        (*my_stats).active_size += sz;
        (*my_stats).ntotal += 1;
        (*my_stats).total_size += sz;
        // set metadata
        (*fm).prev = last_alloc;
        if(last_alloc)
            (*last_alloc).next = fm;
        last_alloc = fm; //update last_alloc

        // true if there are no active allocations
        if(!first_alloc)
            first_alloc = fm;
        (*fm).next = NULL;
        (*fm).file = file;
        (*fm).line = line;
        (*fm).size = sz;
        fm->free_marker = allocated;
        fm->front_buffer = write_buffer;

        void* real_ptr = (void*) (fm + 1);
        //this is where we're going to put the uuid on the end our allocation
        char* end_buffer_ptr = ((char*) real_ptr) + sz;
        *((int*) end_buffer_ptr) = write_buffer;

        if ((*my_stats).heap_min == NULL)
        {
            (*my_stats).heap_min = (char*)real_ptr;
            (*my_stats).heap_max = ((char*) real_ptr) + sz;
        }
        else if((char*) real_ptr < (*my_stats).heap_min)
        {
            (*my_stats).heap_min = (char*)real_ptr;
        }
        else if((char*) real_ptr + sz > (*my_stats).heap_max)
        {
            (*my_stats).heap_max = ((char*) real_ptr) + sz;
        }

        //update counters for modified version of algorithm Frequent
        //Frequent 2a
        //used to test if our current allocation's location is being monitored somewhere or not
        bool monitored = false;
        for (int i = 0; i < COUNT; i++)
        {
            if (file == (char*) counters[i].file && line == counters[i].line)
            {
                monitored = true;
                break;
            }
        }
        if (!monitored)
        {
            for (int i = 0; i < COUNT; i++)
            {
                if (counters[i].count <= 0)
                {
                    counters[i].line = line;
                    counters[i].file = (char*) file;
                    counters[i].size = 0;
                    monitored = true;
                    break;
                }
            }
        }
        //Frequent 2b
        if (monitored)
        {
            for (int i = 0; i < COUNT; i++)
            {
                if (file == counters[i].file && line == counters[i].line)
                {
                    counters[i].count += sz;
                    counters[i].size += sz;
                }
            }
        }
        if (!monitored)
        {
            for (int i = 0; i < COUNT; i++)
            {
                counters[i].count -= (long) sz;
                if (counters[i].count < 0)
                {
                    counters[i].file = (char*) file;
                    counters[i].line = line;
                    counters[i].count *= -1;
                    counters[i].size = sz;
                    break;
                }
            }
        }
        return real_ptr;
    }
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc and friends. If
///    `ptr == NULL`, does nothing. The free was called at location
///    `file`:`line`.
void m61_free (void *ptr, const char *file, int line)
{
    // Correct code will never call free before malloc, so my_stats should not be NULL
    if (my_stats == NULL)
        initialize();
    front_metadata* fm = ((front_metadata*) ptr) - 1;

    if ((*my_stats).heap_min > (char*) ptr || (*my_stats).heap_max < (char*) ptr)
    {
        fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
        abort();
    }
    char* end_loc = ((char*) ptr) + (*fm).size; // the end of the allocation
    if (fm->free_marker != allocated)
    {
        fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
        front_metadata* allocation = first_alloc;
        while(allocation)
        {
            // test030: checks if ptr points to inside allocation
            if ((void*) (allocation + 1) < ptr && (char*) ptr < (char*) (allocation + 1) + (*allocation).size)
            {
                fprintf(stderr, "  %s:%d: %p is %lu bytes inside a %lu byte region allocated here\n", (*allocation).file, (*allocation).line, ptr, (unsigned long) ((char*) ptr - (char*) (allocation + 1)), (*allocation).size);
            }
            allocation = (*allocation).next;
        }
        abort();
    }
    // test031, test032: check for wild wild frees by using linked list previous and nexts
    else if (((*fm).next && (*((*fm).next)).prev != fm) || ((*fm).prev && (*((*fm).prev)).next != fm))
    {
        fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n", file, line, ptr);
    }
    else if (*((int*) end_loc) != write_buffer || fm->front_buffer != write_buffer) //checks for overwrite immediately before or immediately after the allocation
    {
        fprintf(stderr, "MEMORY BUG: %s:%d: detected wild write during free of pointer %p\n", file, line, ptr);
        abort();
    }
    else
    {
        if((*fm).prev && (*fm).next)
        {
            (*((*fm).prev)).next = (*fm).next;
            (*((*fm).next)).prev = (*fm).prev;
        }
        else if ((*fm).prev) // has a previous but no next--this is the last allocation that is being freed
        {
            (*((*fm).prev)).next = NULL;
            last_alloc = (*fm).prev; // update last_alloc
        }
        else if ((*fm).next) // has a next but no previous--this is the first allocation that is being freed
        {
            (*((*fm).next)).prev = NULL;
            first_alloc = (*fm).next; // update first_alloc
        }
        else //this is the only active allocation, since it has neither a prev nor a next
        {
            first_alloc = NULL;
            last_alloc = NULL;
        }
        fm->free_marker = freed;
        base_free(fm);
        (*my_stats).nactive -= 1;
        (*my_stats).active_size -= (*fm).size;
    }
}

/// m61_realloc(ptr, sz, file, line)
///    Reallocate the dynamic memory pointed to by `ptr` to hold at least
///    `sz` bytes, returning a pointer to the new block. If `ptr` is NULL,
///    behaves like `m61_malloc(sz, file, line)`. If `sz` is 0, behaves
///    like `m61_free(ptr, file, line)`. The allocation request was at
///    location `file`:`line`.

void* m61_realloc(void* ptr, size_t sz, const char* file, int line)
{
    void* new_ptr = NULL;
    if (sz)
        new_ptr = m61_malloc(sz, file, line);
    if (ptr && new_ptr) {
        // Copy the data from `ptr` into `new_ptr`.
        // To do that, we must figure out the size of allocation `ptr`.
        // test012
        if ((*my_stats).heap_min > (char*) ptr || (*my_stats).heap_max < (char*) ptr)
        {
            fprintf(stderr, "MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap\n", file, line, ptr);
            abort();
        }
        else
        {
            memcpy(new_ptr, ptr, sz); //changed from ptr_size
        }
    }
    if (ptr) // don't free null pointers
        m61_free(ptr, file, line);
    return new_ptr;
}

/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. The memory
///    is initialized to zero. If `sz == 0`, then m61_malloc may
///    either return NULL or a unique, newly-allocated pointer value.
///    The allocation request was at location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, int line)
{
    initialize();
    // test014
    void* ptr = NULL;
    // check for overflow
    if (nmemb > ((size_t) -1) / sz)
    {
        (*my_stats).nfail += 1;
        (*my_stats).fail_size += nmemb*sz;
        return ptr; // while it's still null, indicating failure to the user
    }
    else
    {
        ptr = m61_malloc(nmemb * sz, file, line);
        if (ptr)
            memset(ptr, 0, nmemb * sz);
        return ptr;
    }
}

/// m61_getstatistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_getstatistics(struct m61_statistics* stats)
{
    if (my_stats == NULL)
        initialize();
    *stats = *my_stats;
}

/// m61_printstatistics()
///    Print the current memory statistics.

void m61_printstatistics(void)
{
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport(void)
{
    front_metadata* leak = first_alloc;
    while(leak)
    {
        // test028, test029: leak checks
        fprintf(stdout, "LEAK CHECK: %s:%d: allocated object %p with size %lu\n", (*leak).file, (*leak).line, leak + 1, (*leak).size);
        leak = (*leak).next;
    }
}

void m61_printhhreport(void)
{
    // bubble sort to sort the output (bubble sort is fine for small n)
    for (int i = 0; i < COUNT - 1; i++)
    {
        for (int j = 0; j < COUNT - i - 1; j++)
        {
            if (counters[j].size > counters[j+1].size)
            {
                counter temp = counters[j+1];
                counters[j+1] = counters[j];
                counters[j] = temp;
            }
        }
    }
    double threshold = 0.01;// don't print any heavy hitter candidates whose percentage of total memory allocations isn't over the threshold
    for (int i = COUNT - 1; i >= 0; i--)
    {
        if(((double) counters[i].size)/my_stats->total_size > threshold)
        {
            fprintf(stdout, "HEAVY HITTER: %s:%d: %li bytes (~%.2f%%)\n", counters[i].file, counters[i].line, counters[i].size, ((double) counters[i].size)/my_stats->total_size*100);
        }
    }
}

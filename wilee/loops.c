#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include "wec.h"
#include "wec_decl.h"

/* Globals for values input */
int cpu_wkset_size;
int mem_wkset_size;
float cpuness;
float memness;
float ioness;
int wkload;
long loop_length;
long num_loops;

/* Globals filled by calibration stage */
float time_per_cpuness_iteration;
float time_per_memness_iteration;
float io_scale;

/* Arrays */
int cpuness_array[CPUNESS_INT_ARRAY_SIZE];
struct mem_arr_struct memness_array[MEMNESS_INT_ARRAY_SIZE];

/* Piping globals */
int seed = 23;
int p = 0;
int WILEE_CALIBRATE;
int CPUNESS_INPUT = 0, MEMNESS_INPUT = 0, LOOPLEN_INPUT = 0;
int LOOPNUM_INPUT = 0, TIME_PER_CPU_LOOP = 0, TIME_PER_MEM_LOOP = 0;
int IO_SCALE = 0;
struct timeval pr, ne;
struct timespec t_val;
struct sigaction act;

int interval_rand(int low_rand, int high_rand)
{
        int r = rand_r(&seed) % high_rand;
	return r < low_rand? (low_rand + r) % high_rand : r;
}

long timeval_diff(struct timeval* p, struct timeval* n)
{
	return 1000000 * (n->tv_sec - p->tv_sec) +
			n->tv_usec - p->tv_usec;
}

/*
 * Find out how many operations correspond to 100% of CPU/Memory/IO-ness
 * respectively.
 */
void calibrate()
{
	int retval;
	if (WILEE_CALIBRATE) {
		printf("Starting Calibration:\n");
		printf("---------------------\n");
	}
	cpu_calibrate();
	mem_calibrate();
	sleep_calibrate();
}

int cpu_inner_loop(long cal, int p)
{
	int i, j, k, tmp, jnk = 0;
	long sum;
	for (j = 0; j < cal; j++) {
		sum = 0;
		for (i = 0; i< CPUNESS_INT_ARRAY_SIZE; i++) {
			tmp = 1;
			for (k = 0; k < p; k++)
				tmp *= cpuness_array[i];
			sum += tmp;		
		}
		if (sum % 2 && sum % 3)
			jnk++;
	}
	return jnk;
}

void cpu_calibrate()
{
	int i;
// Limits for interval_rand()
	int lr = 0, hr= 1000;
// No of loops to calibrate with.
	int calib_length = CPU_CALIBRATION_LOOPS;
// No of loops needed to achieve loop_length
	long long calib_loops;
	for (i = 0; i < CPUNESS_INT_ARRAY_SIZE; i++) {
		cpuness_array[i] = interval_rand(lr, hr);
	}
	p = interval_rand(0,4);

	if (!WILEE_CALIBRATE)
		return;
/* 
 * Calibrate by checking how long it takes to run calib_length number of
 * loops.
 */
	gettimeofday(&pr, NULL);
	cpu_inner_loop(calib_length, p);
	gettimeofday(&ne, NULL);
	time_per_cpuness_iteration = (float)(timeval_diff(&pr, &ne))
			 / (float)calib_length;
	calib_loops = loop_length / time_per_cpuness_iteration;
/* 
 * Verify that our calculation is correct by running the calculated number of
 * loops. The result should be loop_length or close to it at least.
 */
	gettimeofday(&pr, NULL);
	cpu_inner_loop(calib_loops, p);
	gettimeofday(&ne, NULL);

	printf("CPU Calibration\n");
	printf("---------------\n");
	printf("Working set size used: %d\n", CPUNESS_INT_ARRAY_SIZE);
	printf("Time per iteration: %f\n", time_per_cpuness_iteration);
	printf("Number of loops for 100%% CPUness: %lld\n", calib_loops);
	printf("Time for above loops: %ld\n", timeval_diff(&pr, &ne));
}

int mem_inner_loop(long cal_len, long cal_siz, int p)
{
	int i, j, k, l, tmp, jnk = 0;
	long sum;
	l = MEMNESS_INT_ARRAY_SIZE - 1;
	struct mem_arr_struct *curr = &memness_array[l];
	struct mem_arr_struct *st = curr;
	for (j = 0; j < cal_len; j++) {
		sum = 0;
		for (i = 0; i < cal_siz; i++) {
			tmp = 1;
//			for (k = 0; k < p; k++)
//				tmp *= curr->num;
			tmp += curr->num;
			curr = curr->next;
			if (curr == NULL) {
				curr = st;	
				printf("no\n");
			}
			sum += tmp;		
		}
		if (sum % 2 && sum % 3)
			jnk++;
	}
	return jnk;
}

/*
 * Operates on memness_array and looks for nodes that haven't been
 * touched.
 */
int randomize_array(struct mem_arr_struct* arr, int siz)
{
	int i, j, curr_index = 0, next_index, start_index, tmp;
	int limit = MEMNESS_INT_ARRAY_SIZE;
	int from, to;
	struct mem_arr_struct *c;
	int* index_arr = (int*)malloc(MEMNESS_INT_ARRAY_SIZE * sizeof(int));
	printf("Randomizing...%d\n", MEMNESS_INT_ARRAY_SIZE);

	for (i = 0; i < MEMNESS_INT_ARRAY_SIZE; i++) {
		index_arr[i] = i;
	}
	curr_index = start_index = MEMNESS_INT_ARRAY_SIZE - 1;
	for (i = 0; i < MEMNESS_INT_ARRAY_SIZE; i++) {
//		printf("\n%d ", next_index);
//		if (index_arr[next_index] == 1) printf("ooh%d", next_index);
		
		from = index_arr[curr_index];

		tmp = index_arr[limit - 1];
		index_arr[limit - 1] = index_arr[curr_index];
		index_arr[curr_index] = tmp;
		limit--;
		next_index = rand() % limit;
		to = index_arr[next_index];
//		printf("%d,%d->", from, to);
		
		memness_array[from].next = &memness_array[to];
		memness_array[from].touched = to;

		curr_index = next_index;
		if (limit == 1)
			break;		
	}
	free(index_arr);	
	c = &memness_array[start_index];
	i = 0;
/*	printf("\n");
	while(c != NULL) {
		printf("%d ", c->touched);
		c = c->next;
	}	
	printf("\n");
*/
	return start_index;
}

void mem_calibrate(void)
{
	int i, p;
// Limits for interval_rand()
	int lr = 0, hr = 100;
// No of loops to calibrate with.
	int calib_length = MEM_CALIBRATION_LOOPS;
// Working set size used for calibration.
	int calib_wss = MEM_CALIBRATION_WSS;
	long long start_usec, end_usec;
// No of loops needed to achieve loop_length
	long long calib_loops;

/*
 * Initialize the memness_array. This is done in such a way that each structure
 * points to the next one in the array, which is chosen at random. Care is
 * taken to ensure that there are no loops created with these pointers.
 */
	for (i = 0; i < MEMNESS_INT_ARRAY_SIZE; i++) {
		memness_array[i].num = interval_rand(lr, hr);
		memness_array[i].touched = 1;
		memness_array[i].next = NULL;
	}
	randomize_array(memness_array, MEMNESS_INT_ARRAY_SIZE);

	if (!WILEE_CALIBRATE)
		return;
/* 
 * Calibrate by checking how long it takes to run calib_length number of
 * loops on a calib_wss sized working set.
 */

	gettimeofday(&pr, NULL);
	mem_inner_loop(calib_length, calib_wss, p);
	gettimeofday(&ne, NULL);
	time_per_memness_iteration = (float)(timeval_diff(&pr, &ne))
			 / (float)calib_length;
	calib_loops = loop_length / time_per_memness_iteration;
//	calib_loops = 0;
	
	gettimeofday(&pr, NULL);
	mem_inner_loop(calib_loops, calib_wss, p);
	gettimeofday(&ne, NULL);

	printf("------------------\n");
	printf("Memory Calibration\n");
	printf("------------------\n");
	printf("Working set size used: %d\n", calib_wss);
	printf("Time per iteration: %f\n", time_per_memness_iteration);
	printf("Number of loops for 100%% Memory-ness: %lld\n", calib_loops);
	printf("Time for above loops: %ld\n", timeval_diff(&pr, &ne));
}

/*
 * usleep() is totally drunk! 
 * Actually that isn't true.
 * My apologies. Never trust PAPI completely!
 */
void sleep_calibrate()
{
	long long start_usec, end_usec;
	int i, min_gr = 1000;
	float sc;

	if (!WILEE_CALIBRATE)
		return;
	
	printf("------------------\n");
	printf("IO Calibration\n");
	printf("------------------\n");
	
	for (i = 1; i <= 100; i+=10) {
		gettimeofday(&pr, NULL);
		usleep(i * min_gr);
		gettimeofday(&ne, NULL);
		sc = (float)(timeval_diff(&pr, &ne)) / (float)(i * min_gr);
		printf("%d: %ld\n", i * min_gr, timeval_diff(&pr, &ne));
	}
	io_scale = sc;
	printf("Scaling factor used: %f\n", io_scale);
}

int check_input_sanity(int argc, char* argv[])
{
	int n = argc, i;
	while (n > 1) {
		if (!strcmp(argv[argc - n + 1], "--calibrate")) {
			WILEE_CALIBRATE = 1;
			n--;
		}
		else if (!strcmp(argv[argc - n + 1], "-C") ||
				!strcmp(argv[argc - n + 1], "--cpu")) {
			cpuness = atof(argv[argc - n + 2]);
			if (cpuness < 0 || cpuness > 1) {
				fprintf(stderr, "BAD CPUness value! %f %s\n", cpuness, argv[argc - n + 1]);
				return -1;
			}
			CPUNESS_INPUT = 1;
			n -= 2;
		}
		else if (!strcmp(argv[argc - n + 1], "-M") ||
				!strcmp(argv[argc - n + 1], "--mem")) {
			memness = atof(argv[argc - n + 2]);
			if (memness < 0 || memness > 1) {
				fprintf(stderr, "BAD Mem-ness value!\n");
				return -1;
			}
			MEMNESS_INPUT = 1;
			n -= 2;
		}
		else if (!strcmp(argv[argc - n + 1], "-l") ||
				!strcmp(argv[argc - n + 1], "--loop_length")) {
			loop_length = atoi(argv[argc - n + 2]);
			if (loop_length < WEC_MINIMUM_LOOP_GRANULARITY) {
				fprintf(stderr, "Setting loop granularity to %d\n", 
						WEC_MINIMUM_LOOP_GRANULARITY);
				loop_length = WEC_MINIMUM_LOOP_GRANULARITY;
			}
			LOOPLEN_INPUT = 1;
			n -= 2;
		}
		else if (!strcmp(argv[argc - n + 1], "-n") ||
				!strcmp(argv[argc - n + 1], "--loops")) {
			num_loops = atoi(argv[argc - n + 2]);
			LOOPNUM_INPUT = 1;
			n -= 2;
		}
		else if (!strcmp(argv[argc - n + 1], "-c") ||
				!strcmp(argv[argc - n + 1], "--cpu_calib")) {
			time_per_cpuness_iteration = atof(argv[argc - n + 2]);
			TIME_PER_CPU_LOOP = 1;
			n -= 2;
		}
		else if (!strcmp(argv[argc - n + 1], "-m") ||
				!strcmp(argv[argc - n + 1], "--mem_calib")) {
			time_per_memness_iteration = atof(argv[argc - n + 2]);
			TIME_PER_MEM_LOOP = 1;
			n -= 2;
		}
		else if (!strcmp(argv[argc - n + 1], "-i") ||
				!strcmp(argv[argc - n + 1], "--sleep_calib")) {
			io_scale = atof(argv[argc - n + 2]);
			IO_SCALE = 1;
			n -= 2;
		}
	}
	if (!(CPUNESS_INPUT && MEMNESS_INPUT 
			&& LOOPLEN_INPUT && LOOPNUM_INPUT)) {
		if (WILEE_CALIBRATE)
			goto out;
		fprintf(stderr, "Insufficient input parameters! Ignoring.\n");
		return -1;
	}
	if (!WILEE_CALIBRATE && 
			!(TIME_PER_CPU_LOOP && TIME_PER_MEM_LOOP && 
			IO_SCALE)) {
		fprintf(stderr, "Insufficient calibration parameters!\n");
		return -1;
	}
	if (CPUNESS_INPUT && MEMNESS_INPUT) {
		ioness = 1.0 - (cpuness + memness);
		if (ioness < 0) {
			fprintf(stderr, "Incorrect cpuness and memness \
					values!\n");
			return -1;
		}
	}
out:
	if (!loop_length)
		loop_length = WEC_MINIMUM_LOOP_GRANULARITY;
	return 1;
}


/*
 * Actually run the loops after calibration values have been either supplied
 * or calculated.
 */
void do_loops(void)
{
	int i, j;
	float cpu_length, mem_length, io_length;
	int cpu_loops, mem_loops;
	long long start_usec, end_usec;

	cpu_length = loop_length * cpuness;
	mem_length = loop_length * memness;
	io_length = loop_length * ioness;
	cpu_loops = cpu_length / time_per_cpuness_iteration;
	mem_loops = mem_length / time_per_memness_iteration;
	
	gettimeofday(&pr, NULL);
	for (i = 0; i < num_loops; i++) {
		cpu_inner_loop(cpu_loops, p);
		mem_inner_loop(mem_loops, MEM_CALIBRATION_WSS, p);
		if (io_length)
			usleep((int)(io_length / io_scale));		
	}
	gettimeofday(&ne, NULL);

	printf("\n\n------------------\n");
	printf("Workload\n");
	printf("------------------\n");
	printf("CPUness: %f\n", cpuness);
	printf("Mem-ness: %f\n", memness);
	printf("IOness: %f\n", ioness);
	printf("Loop length: %ld\n", loop_length);
	printf("Number of loops: %ld\n", num_loops);
	printf("Number of CPU iterations: %d\n", cpu_loops);
	printf("Number of MEM iteration: %d\n", mem_loops);
	printf("Time for above loops: %ld\n", timeval_diff(&pr, &ne));
	printf("Time per loop: %ld\n", timeval_diff(&pr, &ne) / num_loops);

}


int main(int argc, char *argv[])
{
	char c;
	system("clear");
	if (check_input_sanity(argc,argv) < 0) {
		exit(1);
	}
	calibrate();
	if (CPUNESS_INPUT && MEMNESS_INPUT && LOOPLEN_INPUT && LOOPNUM_INPUT) {
		printf("Hit any key to start!\n");
		c = getchar();
		do_loops();
	}
//	c = getchar();
}	

/* WileE Benchmark.
 * Author: Hrishikesh Amur
 *
 * 1. This contains all the parameters for WileE. 
 * 2. All times are in microseconds unless specified.
 * 3. All sizes are in kilobytes unless specified.
 */

/****************************************************************************/
/* Configurable Parameters						    */
/****************************************************************************/
#define L1_DATA_CACHE_SIZE			32
#define LL_CACHE_SIZE				4096
#define MEM_SIZE				4109720			

/* Assuming sizeof(int) is 4, defines a 16KB array */
//#define CPUNESS_INT_ARRAY_SIZE			4096
#define CPUNESS_INT_ARRAY_SIZE			1024
/* Assuming sizeof(struct mem_arr_struct) is 12, defines a 512MB array. This
 *  will also be the maximum allowed working set size. */
#define MEMNESS_INT_ARRAY_SIZE			44739242
//#define MEMNESS_INT_ARRAY_SIZE			110
/* Number of loops to calibrate with */ 
#define CPU_CALIBRATION_LOOPS			1000
#define MEM_CALIBRATION_LOOPS			1000
#define MEM_CALIBRATION_WSS			128

/****************************************************************************/
/* Fixed Parameters, aka DO NOT CHANGE!					    */
/****************************************************************************/

/* This is the smallest size loop that can be accurately modeled for any given
 * combination of CPU/Memory/IO-ness. Larger units can be used.
 */
#define WEC_MINIMUM_LOOP_GRANULARITY		1000

/* Workloads:
 * These will involve for now, mainly CPU and Memory bound workloads.
 */

/* CPU-intensive integer arithmetic operations on a working set guaranteed to
 * fit in L1 data cache. The Memory-ness associated with this workload is got
 * through memory accesses on a fixed size array which is much larger than the
 * LL-cache and consists of random accesses to cancel the benefit of pre-fetch
 * ing.
 */ 
#define	WEC_CPU_INT_OPS				1
/* Memory-intensive square root operations on a working set much larger than
 * the last level cache. The elements of the working set are accessed
 * sequentially which means that effective pre-fetching could hide most of 
 * the latency.
 */
#define WEC_MEM_SQROOT_SEQ_OPS			10
/* Memory-intensive square root operations on a working set much larger than
 * the last level cache. The elements of the working set are accessed
 * randomly which means that a large fraction of accesses actually go to
 * memory.
 */
#define WEC_MEM_SQROOT_RND_OPS			11

/****************************************************************************/
/* Structure definitions						    */
/****************************************************************************/

struct mem_arr_struct {
	int num;
	struct mem_arr_struct* next;
	int touched;
};	

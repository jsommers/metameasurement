This code is adapted from "https://github.com/SudarsunKannan/wilee" with author's permission

# Calibration Tips:

1. Before calibration, ensure that the CPU is running at maximum frequency and
   set the governor to "performance" if necessary.
2. Run the calibration at least two times to check if the same values are being
   obtained.
	From the calibration, the value to be used with the -c option is the
	"Time per iteration" from the output. For the sleep calibration, the 
	value of "Scaling factor" can be used. Ideally this should be close to
	1.
3. When the actual run is made, make sure that the loop_length is close to the
   time per loop shown. This can be tried with different combinations, but at 
   least full CPUness MEMness and IOness have to be verified. If it is not, 
   this is most probably because of the "per-loop" time being too large which
   means that the 100%-loop count does not take 1ms as it should.
4. If PAPI is not installed on your system, before making please comment out
   the $LIB line in the Makefile. I haven't gotten down to writing a configure
   for this yet.


Options:
--------
	-C, --cpu
		Specifies the desired CPUness.

	-M, --mem
		Specifies the desired MEMness.

	-l, --loop_length
		Specifies the smallest loop length in microseconds.

	-n, --loops
		Specifies the number of times to iterate over the loop.

	-c, --cpu_calib
		If calibration is not desired, then these values have to be
		specified. This is the result of calibration.

	-m, --mem_calib
		If calibration is not desired, then these values have to be
		specified. This is the result of calibration.

	-i, --sleep_calib
		If calibration is not desired, then these values have to be
		specified. This is the result of calibration.

	--calibrate
		Perform calibration before running the actual loops. This will
		calculate how many internal loops are required for 100% of each
		of CPUness, MEMness and IOness for the given loop length.
	
	--no_papi
		Do not initialize or use the PAPI library. If the PAPI library
		has not been installed on the system, then this is a required
		option. The benchmark assumes that PAPI is enabled by default.

	--papi_periodic
		Use this option if the benchmark is being used as a target 
		workload. This requies PAPI to be installed. It initializes
		the library and periodically prints out any value that needs to
		be monitored.

Examples:
---------

#### Calibrate
./wileE --calibrate

Starting Calibration:

CPU Calibration:
Working set size used: 1024
Time per iteration: 12.103000
Number of loops for 100% CPUness: 82
Time for above loops: 988
L2DCM:13 for 1000 loops
L2DCM:1 for 82 loops
Randomizing...44739242

Memory Calibration:
Working set size used: 128
Time per iteration: 20.566000
Number of loops for 100% Memory-ness: 48
Time for above loops: 1001
L2DCM:326456 for 1000 loops
L2DCM:15658 for 48 loops

IO Calibration:
1000: 1038
11000: 11027
21000: 21028
31000: 31027
41000: 41028
51000: 51027
61000: 61028
71000: 71028
81000: 81029
91000: 91027
Scaling factor used: 1.000297

#### Execute
./wileE -C 0.0 -M 1.0 -l 100000 -n 100 -c 12.103 -m 20.566 -i 1.00 --no_papi

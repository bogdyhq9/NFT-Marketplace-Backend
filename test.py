import datetime
import json
import random
import string
import multiprocessing as mp
from functools import partial
from collections import Counter
import os

from ca_fingerprint import CAFingerprint


def hamming_distance(bytes1: bytes, bytes2: bytes) -> int:
    """Calculate Hamming distance between two byte arrays."""
    if len(bytes1) != len(bytes2):
        return -1
    
    distance = 0
    for b1, b2 in zip(bytes1, bytes2):
        xor = b1 ^ b2
        distance += bin(xor).count('1')
    
    return distance


def generate_random_string(length: int = None) -> str:
    """Generate a random string for testing."""
    if length is None:
        length = random.randint(5, 50)
    
    return ''.join(random.choices(
        string.ascii_letters + string.digits + string.punctuation + ' ',
        k=length
    ))


def generate_similar_string(base_string: str, change_type: str = 'flip') -> str:
    """Generate a string similar to base_string with minimal changes."""
    if not base_string:
        return 'x'
    
    s = list(base_string)
    
    if change_type == 'flip' and len(s) > 0:
        # Flip one character
        idx = random.randint(0, len(s) - 1)
        if s[idx].isalpha():
            s[idx] = s[idx].swapcase()
        else:
            s[idx] = chr((ord(s[idx]) + 1) % 128)
    
    elif change_type == 'insert':
        # Insert one character
        idx = random.randint(0, len(s))
        s.insert(idx, random.choice(string.ascii_letters))
    
    elif change_type == 'delete' and len(s) > 1:
        # Delete one character
        idx = random.randint(0, len(s) - 1)
        s.pop(idx)
    
    return ''.join(s)


# Global variable to hold the shared CA instance
_shared_ca_fp = None


def init_worker(ca_instance):
    """Initialize worker process with shared CA instance."""
    global _shared_ca_fp
    _shared_ca_fp = ca_instance


def collision_worker(input_batch: list, worker_id: int = 0) -> dict:
    """Worker function for collision detection test using shared CA instance."""
    global _shared_ca_fp
    
    # Seed random generator differently for each worker
    random.seed(worker_id * 12345 + int(datetime.datetime.now().timestamp()))
    
    fingerprints = {}
    collisions = []
    duplicate_inputs = 0
    
    for test_input in input_batch:
        if test_input in fingerprints:
            duplicate_inputs += 1
            continue
        
        try:
            fp = _shared_ca_fp.generate_fingerprint(test_input)
            fp_hex = fp.hex()
            
            if fp_hex in fingerprints:
                collisions.append({
                    'input1': fingerprints[fp_hex],
                    'input2': test_input,
                    'fingerprint': fp_hex,
                    'worker_id': worker_id
                })
            else:
                fingerprints[fp_hex] = test_input
                
        except Exception as e:
            print(f"Worker {worker_id}: Error generating fingerprint: {e}")
            continue
    
    return {
        'fingerprints': fingerprints,
        'collisions': collisions,
        'duplicate_inputs': duplicate_inputs,
        'worker_id': worker_id
    }


def bit_flip_worker(input_pairs: list, worker_id: int = 0) -> list:
    """Worker function for bit flip sensitivity test using shared CA instance."""
    global _shared_ca_fp
    random.seed(worker_id * 54321 + int(datetime.datetime.now().timestamp()))
    
    hamming_distances = []
    
    for base_string, similar_string in input_pairs:
        try:
            fp1 = _shared_ca_fp.generate_fingerprint(base_string)
            fp2 = _shared_ca_fp.generate_fingerprint(similar_string)
            
            hamming_dist = hamming_distance(fp1, fp2)
            if hamming_dist >= 0:
                hamming_distances.append(hamming_dist)
                
        except Exception as e:
            print(f"Worker {worker_id}: Error in bit flip test: {e}")
            continue
    
    return hamming_distances


def statistical_worker(fingerprint_batch: list, output_size: int) -> list:
    """Worker function for statistical analysis."""
    bit_counts = [0] * (output_size * 8)
    
    for fp_hex in fingerprint_batch:
        try:
            fp_bytes = bytes.fromhex(fp_hex)
            for byte_idx, byte_val in enumerate(fp_bytes):
                for bit_idx in range(8):
                    if byte_val & (1 << (7 - bit_idx)):
                        bit_counts[byte_idx * 8 + bit_idx] += 1
        except Exception as e:
            print(f"Error processing fingerprint {fp_hex}: {e}")
            continue
    
    return bit_counts


def run_comprehensive_test_parallel(num_tests: int = 10000, num_processes: int = None):
    """Run comprehensive fingerprint testing with parallel processing using single CA instance."""
    if num_processes is None:
        num_processes = mp.cpu_count()
    
    print(f"Starting parallel CA fingerprint testing with {num_tests} samples...")
    print(f"Using {num_processes} processes on {mp.cpu_count()} available cores")
    print("Using SINGLE shared CAFingerprint instance across all workers")
    print("=" * 70)
    
    # Initialize single fingerprint generator
    ca_fp = CAFingerprint()
    
    # Test results storage
    results = {
        'test_info': {
            'timestamp': datetime.datetime.now().isoformat(),
            'num_tests': num_tests,
            'num_processes': num_processes,
            'shared_ca_instance': True,
            'ca_width': ca_fp.ca_width,
            'output_size': ca_fp.output_size,
            'iterations': ca_fp.iterations
        },
        'collision_test': {},
        'bit_flip_test': {},
        'statistical_analysis': {},
        'performance': {}
    }
    
    start_time = datetime.datetime.now()
    
    # Phase 1: Parallel Collision Detection Test
    print("Phase 1: Parallel Collision Detection Test")
    print("-" * 40)
    
    collision_start = datetime.datetime.now()
    
    # Pre-generate all test inputs
    print("  Generating test inputs...")
    test_inputs = []
    for i in range(num_tests):
        if i % 20000 == 0:
            print(f"    Generated {i:,} test inputs...")
        test_inputs.append(generate_random_string())
    
    # Distribute inputs across workers
    batch_size = len(test_inputs) // num_processes
    input_batches = []
    
    for i in range(num_processes):
        start_idx = i * batch_size
        if i == num_processes - 1:  # Last worker gets remaining inputs
            end_idx = len(test_inputs)
        else:
            end_idx = (i + 1) * batch_size
        input_batches.append(test_inputs[start_idx:end_idx])
    
    print(f"  Distributing {num_tests} inputs across {num_processes} workers...")
    
    # Execute collision detection in parallel with shared CA instance
    with mp.Pool(processes=num_processes, initializer=init_worker, initargs=(ca_fp,)) as pool:
        tasks = [(batch, i) for i, batch in enumerate(input_batches)]
        collision_results = pool.starmap(collision_worker, tasks)
    
    # Merge results from all workers
    all_fingerprints = {}
    all_collisions = []
    total_duplicates = 0
    
    for result in collision_results:
        # Check for cross-worker collisions
        for fp_hex, input_str in result['fingerprints'].items():
            if fp_hex in all_fingerprints:
                all_collisions.append({
                    'input1': all_fingerprints[fp_hex],
                    'input2': input_str,
                    'fingerprint': fp_hex,
                    'cross_worker': True
                })
            else:
                all_fingerprints[fp_hex] = input_str
        
        # Add worker-specific collisions
        all_collisions.extend(result['collisions'])
        total_duplicates += result['duplicate_inputs']
    
    collision_rate = len(all_collisions) / len(all_fingerprints) if all_fingerprints else 0
    unique_fingerprints = len(all_fingerprints)
    
    collision_time = (datetime.datetime.now() - collision_start).total_seconds()
    
    results['collision_test'] = {
        'total_inputs': num_tests,
        'duplicate_inputs': total_duplicates,
        'unique_fingerprints': unique_fingerprints,
        'collisions_found': len(all_collisions),
        'collision_rate': collision_rate,
        'collisions': all_collisions[:10],  # Store first 10 collisions
        'processing_time_seconds': collision_time
    }
    
    print(f"  Unique fingerprints: {unique_fingerprints:,}")
    print(f"  Collisions found: {len(all_collisions)}")
    print(f"  Collision rate: {collision_rate:.2e}")
    print(f"  Phase 1 time: {collision_time:.2f} seconds")
    
    # Phase 2: Parallel Bit Flip Sensitivity Test
    print("\nPhase 2: Parallel Bit Flip Sensitivity Test")
    print("-" * 40)
    
    bit_flip_start = datetime.datetime.now()
    bit_flip_tests = min(10000, num_tests // 10)
    
    # Pre-generate all input pairs for bit flip testing
    print("  Generating bit flip test pairs...")
    input_pairs = []
    for i in range(bit_flip_tests):
        base_string = generate_random_string()
        similar_string = generate_similar_string(base_string, 'flip')
        input_pairs.append((base_string, similar_string))
    
    # Distribute pairs across workers
    pairs_per_worker = len(input_pairs) // num_processes
    pair_batches = []
    
    for i in range(num_processes):
        start_idx = i * pairs_per_worker
        if i == num_processes - 1:  # Last worker gets remaining pairs
            end_idx = len(input_pairs)
        else:
            end_idx = (i + 1) * pairs_per_worker
        pair_batches.append(input_pairs[start_idx:end_idx])
    
    print(f"  Running {bit_flip_tests} bit flip tests across {num_processes} workers...")
    
    with mp.Pool(processes=num_processes, initializer=init_worker, initargs=(ca_fp,)) as pool:
        tasks = [(batch, i) for i, batch in enumerate(pair_batches)]
        hamming_results = pool.starmap(bit_flip_worker, tasks)
    
    # Combine all Hamming distances
    all_hamming_distances = []
    for distances in hamming_results:
        all_hamming_distances.extend(distances)
    
    bit_flip_time = (datetime.datetime.now() - bit_flip_start).total_seconds()
    
    # Bit flip analysis
    if all_hamming_distances:
        avg_hamming = sum(all_hamming_distances) / len(all_hamming_distances)
        min_hamming = min(all_hamming_distances)
        max_hamming = max(all_hamming_distances)
        total_bits = ca_fp.output_size * 8
        avg_flip_percentage = (avg_hamming / total_bits) * 100
        
        results['bit_flip_test'] = {
            'tests_performed': len(all_hamming_distances),
            'average_hamming_distance': avg_hamming,
            'min_hamming_distance': min_hamming,
            'max_hamming_distance': max_hamming,
            'total_output_bits': total_bits,
            'average_flip_percentage': avg_flip_percentage,
            'processing_time_seconds': bit_flip_time,
            'hamming_distribution': {
                'low_sensitivity': sum(1 for d in all_hamming_distances if d < total_bits * 0.3),
                'good_sensitivity': sum(1 for d in all_hamming_distances if total_bits * 0.3 <= d <= total_bits * 0.7),
                'high_sensitivity': sum(1 for d in all_hamming_distances if d > total_bits * 0.7)
            }
        }
        
        print(f"  Average Hamming distance: {avg_hamming:.2f}")
        print(f"  Average bit flip percentage: {avg_flip_percentage:.2f}%")
        print(f"  Range: {min_hamming} - {max_hamming}")
        print(f"  Phase 2 time: {bit_flip_time:.2f} seconds")
    
    # Phase 3: Parallel Statistical Analysis
    print("\nPhase 3: Parallel Statistical Analysis")
    print("-" * 40)
    
    stats_start = datetime.datetime.now()
    sample_size = min(1000, len(all_fingerprints))
    sample_fps = list(all_fingerprints.keys())[:sample_size]
    
    # Split fingerprints into batches for parallel processing
    batch_size = max(1, sample_size // num_processes)
    fp_batches = [sample_fps[i:i + batch_size] for i in range(0, sample_size, batch_size)]
    
    with mp.Pool(processes=num_processes) as pool:
        stat_worker = partial(statistical_worker, output_size=ca_fp.output_size)
        bit_count_results = pool.map(stat_worker, fp_batches)
    
    # Combine bit counts from all workers
    total_bit_counts = [0] * (ca_fp.output_size * 8)
    for bit_counts in bit_count_results:
        for i, count in enumerate(bit_counts):
            total_bit_counts[i] += count
    
    stats_time = (datetime.datetime.now() - stats_start).total_seconds()
    
    # Calculate bit balance
    bit_percentages = [(count / sample_size) * 100 for count in total_bit_counts]
    avg_bit_percentage = sum(bit_percentages) / len(bit_percentages)
    bit_variance = sum((p - 50) ** 2 for p in bit_percentages) / len(bit_percentages)
    
    results['statistical_analysis'] = {
        'sample_size': sample_size,
        'processing_time_seconds': stats_time,
        'bit_balance': {
            'average_bit_percentage': avg_bit_percentage,
            'bit_variance_from_50': bit_variance,
            'well_balanced_bits': sum(1 for p in bit_percentages if 45 <= p <= 55),
            'total_bits': len(bit_percentages)
        }
    }
    
    print(f"  Bit balance analysis (sample of {sample_size}):")
    print(f"    Average bit percentage: {avg_bit_percentage:.2f}%")
    print(f"    Variance from 50%: {bit_variance:.2f}")
    print(f"    Well-balanced bits (45-55%): {results['statistical_analysis']['bit_balance']['well_balanced_bits']}/{len(bit_percentages)}")
    print(f"  Phase 3 time: {stats_time:.2f} seconds")
    
    # Performance metrics
    end_time = datetime.datetime.now()
    total_time = (end_time - start_time).total_seconds()
    fps_per_second = num_tests / total_time
    
    results['performance'] = {
        'total_time_seconds': total_time,
        'collision_phase_seconds': collision_time,
        'bit_flip_phase_seconds': bit_flip_time,
        'statistical_phase_seconds': stats_time,
        'fingerprints_per_second': fps_per_second,
        'average_time_per_fingerprint_ms': (total_time / num_tests) * 1000,
        'parallel_efficiency': {
            'processes_used': num_processes,
            'theoretical_speedup': num_processes,
            'estimated_sequential_time': total_time * num_processes,
            'parallel_overhead_estimate': max(0, total_time - (collision_time + bit_flip_time + stats_time))
        }
    }
    
    print(f"\nPerformance:")
    print(f"  Total time: {total_time:.2f} seconds")
    print(f"  Fingerprints/second: {fps_per_second:.2f}")
    print(f"  Average time per fingerprint: {(total_time / num_tests) * 1000:.3f} ms")
    print(f"  Parallel efficiency: ~{(fps_per_second * total_time / num_tests / num_processes * 100):.1f}%")
    
    # Save results to file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ca_fingerprint_shared_parallel_results_{timestamp}.json"
    
    # Convert datetime objects to strings for JSON serialization
    results_serializable = json.loads(json.dumps(results, default=str))
    
    with open(filename, 'w') as f:
        json.dump(results_serializable, f, indent=2)
    
    print(f"\nResults saved to: {filename}")
    
    # Summary
    print("\n" + "=" * 70)
    print("SHARED INSTANCE PARALLEL TEST SUMMARY")
    print("=" * 70)
    print(f"Single CAFingerprint instance used across all {num_processes} processes")
    print(f"Collision resistance: {len(all_collisions)} collisions in {unique_fingerprints:,} fingerprints")
    
    if all_hamming_distances:
        print(f"Bit flip sensitivity: {avg_flip_percentage:.1f}% average bit change")
    else:
        print("No bit flip sensitivity data available")
    
    print(f"Bit distribution: {bit_variance:.2f} variance from ideal 50%")
    print(f"Used {num_processes} processes for {fps_per_second:.1f} fingerprints/second")
    
    if len(all_collisions) == 0:
        print("No collisions detected!")
    elif collision_rate < 1e-6:
        print("Very low collision rate")
    else:
        print("Higher than expected collision rate")
    
    if all_hamming_distances:
        if 40 <= avg_flip_percentage <= 60:
            print("EXCELLENT: Good bit flip sensitivity!")
        elif 30 <= avg_flip_percentage <= 70:
            print("Acceptable bit flip sensitivity")
        else:
            print("Poor bit flip sensitivity")
    
    return results


if __name__ == "__main__":
    # Run the parallel comprehensive test with shared CA instance
    num_processes = mp.cpu_count()  # Use all available cores
    # num_processes = 4  # Or specify a specific number
    
    print(f"System has {mp.cpu_count()} CPU cores available")
    
    test_results = run_comprehensive_test_parallel(
        num_tests=10000,
        num_processes=num_processes
    )
    
    print("\nShared instance parallel test completed successfully!")
    print("Check the generated JSON file for detailed results.")
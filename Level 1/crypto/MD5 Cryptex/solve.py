import hashlib
import itertools
import multiprocessing as mp
import requests
from bs4 import BeautifulSoup
import time

def crack_range(start_idx, end_idx, target_hash, alphabet, result_queue):
    """Crack a range with optimization"""
    length = 6
    
    def idx_to_password(idx):
        password = []
        temp_idx = idx
        for _ in range(length):
            password.append(alphabet[temp_idx % len(alphabet)])
            temp_idx //= len(alphabet)
        return ''.join(reversed(password))
    
    # Create MD5 hasher once for reuse
    hasher = hashlib.md5()
    
    count = 0
    for idx in range(start_idx, end_idx):
        password = idx_to_password(idx)
        
        # Reset hasher and calculate hash
        hasher = hashlib.md5()
        hasher.update(password.encode())
        md5_hash = hasher.hexdigest()
        
        count += 1
        
        # Progress report every 100k attempts
        if count % 100000 == 0:
            print(f"Process {mp.current_process().name}: Tried {count:,} | Current: {password}")
        
        if md5_hash == target_hash:
            result_queue.put(password)
            return
    
    result_queue.put(None)

def crack_md5(target_hash, max_length=6, num_processes=None):
    """Maximally optimized version"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    if num_processes is None:
        num_processes = mp.cpu_count()
    
    total_combinations = len(alphabet) ** max_length
    chunk_size = total_combinations // num_processes
    
    print(f"=== OPTIMIZED MD5 CRACKER ===")
    print(f"Target: {target_hash}")
    print(f"Processes: {num_processes}")
    print(f"Total combinations: {total_combinations:,}")
    print(f"Estimated time: ~{total_combinations / (1000000 * num_processes):.1f} minutes")
    
    # Create queue to receive results
    result_queue = mp.Queue()
    processes = []
    
    start_time = time.time()
    
    # Start the processes
    for i in range(num_processes):
        start_idx = i * chunk_size
        end_idx = start_idx + chunk_size if i < num_processes - 1 else total_combinations
        
        process = mp.Process(
            target=crack_range,
            args=(start_idx, end_idx, target_hash, alphabet, result_queue)
        )
        process.start()
        processes.append(process)
    
    # Wait for results
    result = None
    completed_processes = 0
    
    while completed_processes < num_processes:
        try:
            # Timeout 1 second to check periodically
            temp_result = result_queue.get(timeout=1)
            if temp_result is not None:
                result = temp_result
                print(f"\n FOUND PASSWORD: {result}")
                break
            else:
                completed_processes += 1
        except:
            continue
    
    # Terminate all processes
    for process in processes:
        process.terminate()
        process.join()
    
    end_time = time.time()
    print(f"Time taken: {end_time - start_time:.2f} seconds")
    
    return result

def submit_password(url, password):
    """Submit with improved error handling"""
    try:
        data = {
            'val1': password[0], 'val2': password[1], 'val3': password[2],
            'val4': password[3], 'val5': password[4], 'val6': password[5]
        }
        
        response = requests.post(f"{url.rstrip('/')}/submit", data=data, timeout=10)
        
        if 'DH{' in response.text:
            # Extract flag using regex
            import re
            flag_match = re.search(r'DH\{[^}]+\}', response.text)
            if flag_match:
                return flag_match.group(0)
        
        return None
    except Exception as e:
        print(f"Submit error: {e}")
        return None

def main():
    url = "http://host8.dreamhack.games:21273"
    
    print("=== MD5 CRYPTEX OPTIMIZER ===")
    
    # Get target hash
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        target_hash = soup.find('p').text.strip()
        print(f"Target hash: {target_hash}")
    except:
        target_hash = input("Enter MD5 hash manually: ").strip()
    
    # Crack with optimizations
    start_total = time.time()
    password = crack_md5(target_hash)
    
    if password:
        print(f"\nSubmitting password: {password}")
        flag = submit_password(url, password)
        
        if flag:
            print(f"\n SUCCESS! FLAG: {flag}")
        else:
            print(f"Password found but submission failed: {password}")
    else:
        print("Failed to crack the hash!")
    
    total_time = time.time() - start_total
    print(f"Total execution time: {total_time:.2f} seconds")

if __name__ == "__main__":
    main()
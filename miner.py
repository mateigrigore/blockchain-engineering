import hashlib
import struct
import multiprocessing
import time
import sys

# --- CONFIGURATION ---
EMAIL = "m.grigore@student.tudelft.nl"
GITHUB_URL = "https://github.com/mateigrigore/blockchain-engineering"
# ---------------------

def miner_worker(email: str, url: str, start_offset: int, step: int, found_event: multiprocessing.Event, result_queue: multiprocessing.Queue):
    """
    Worker process that searches for a valid nonce.
    """
    # 1. Prepare the prefix: email_utf8 || "\n" || github_url_utf8 || "\n"
    prefix = f"{email}\n{url}\n".encode('utf-8')
    
    # 2. Precompute the base hash state. 
    # This is a massive optimization: we don't re-hash the strings every iteration.
    base_hash = hashlib.sha256(prefix)
    
    nonce = start_offset
    
    # Localizing functions inside the loop scope speeds up execution in Python
    pack = struct.Struct('>q').pack 
    
    try:
        while not found_event.is_set():
            # Process in batches to avoid checking the multiprocessing event too often (which is slow)
            for _ in range(100_000):
                # Copy the precomputed state and add the 8-byte big-endian nonce
                h = base_hash.copy()
                h.update(pack(nonce))
                d = h.digest()
                
                # Check difficulty: First 3 bytes are 0x00, 4th byte is < 16 (0x10)
                if d[:3] == b'\x00\x00\x00' and d[3] < 16:
                    result_queue.put((nonce, d.hex()))
                    found_event.set()
                    return
                
                nonce += step
                
    except KeyboardInterrupt:
        # Silently handle keyboard interrupt in child processes
        pass

def main():
    print(f"Target Email: {EMAIL}")
    print(f"Target URL:   {GITHUB_URL}")
    print("-" * 50)
    
    num_cores = multiprocessing.cpu_count()
    print(f"Starting mining fleet with {num_cores} cores...")
    
    # Shared state to communicate between processes
    found_event = multiprocessing.Event()
    result_queue = multiprocessing.Queue()
    
    processes = []
    start_time = time.time()
    
    # Boot up a worker process for each CPU core
    for i in range(num_cores):
        # Each core gets a different starting offset and jumps by 'num_cores'
        # e.g., Core 0 checks 0, 4, 8... Core 1 checks 1, 5, 9...
        p = multiprocessing.Process(
            target=miner_worker, 
            args=(EMAIL, GITHUB_URL, i, num_cores, found_event, result_queue)
        )
        p.start()
        processes.append(p)
    
    try:
        # Monitor progress while waiting for a worker to find the answer
        while not found_event.wait(timeout=5.0):
            elapsed = time.time() - start_time
            print(f"Mining... {elapsed:.1f}s elapsed (Still crunching hashes)")
            
    except KeyboardInterrupt:
        print("\nStopping mining process...")
        found_event.set()
    
    # If the queue has a result, unpack and print it
    if not result_queue.empty():
        winning_nonce, winning_hash = result_queue.get()
        elapsed = time.time() - start_time
        print("\n" + "=" * 50)
        print("SUCCESS! Nonce found!")
        print("=" * 50)
        print(f"Nonce (Integer): {winning_nonce}")
        print(f"Hex Hash:        {winning_hash}")
        print(f"Time taken:      {elapsed:.2f} seconds")
        print("=" * 50)
    
    # Cleanup processes
    for p in processes:
        p.join()

if __name__ == '__main__':
    # Required for Windows multiprocessing compatibility
    multiprocessing.freeze_support()
    
    if EMAIL == "your.name@student.tudelft.nl":
        print("⚠️  Please update the EMAIL and GITHUB_URL variables in the script before running.")
        sys.exit(1)
        
    main()
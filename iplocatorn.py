#!/usr/bin/env python3

import os
import math
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Split IP list and process in parallel')
    parser.add_argument('-L', '--input', required=True, help='Path to the input file containing IP addresses (one per line)')
    parser.add_argument('-O', '--output', required=True, help='Base path for output Excel files (e.g., "output_part")')
    parser.add_argument('-P', '--parts', type=int, default=10, help='Number of parts to split the IPs into (default: 10)')
    return parser.parse_args()

def read_ip_addresses(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def split_list(data, num_parts):
    """Splits the data into approximately equal parts."""
    chunk_size = math.ceil(len(data) / num_parts)
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

def write_chunks(chunks, base_name):
    paths = []
    for idx, chunk in enumerate(chunks):
        chunk_path = f"{base_name}_part_{idx + 1}.txt"
        with open(chunk_path, 'w') as file:
            file.write('\n'.join(chunk) + '\n')
        paths.append(chunk_path)
    return paths

def launch_terminals(chunk_paths, base_output_name):
    for idx, chunk_path in enumerate(chunk_paths):
        output_file = f"{base_output_name}_part_{idx + 1}.xlsx"
        command = f'gnome-terminal -- bash -c "python3 iplocatornew.py -L {chunk_path} -O {output_file}; exec bash"'
        os.system(command)

def main():
    args = parse_arguments()
    ip_list = read_ip_addresses(args.input)
    
    if not ip_list:
        print("No IP addresses found in the input file.")
        return
    
    print(f"Splitting {len(ip_list)} IPs into {args.parts} parts...")
    chunks = split_list(ip_list, args.parts)
    
    print("Writing split files...")
    chunk_paths = write_chunks(chunks, "chunked_ips")
    
    print("Launching terminals for parallel processing...")
    launch_terminals(chunk_paths, args.output)

if __name__ == "__main__":
    main()

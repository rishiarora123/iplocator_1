#!/usr/bin/env python3

import argparse
import requests
import pandas as pd
import sys
import time

def parse_arguments():
    parser = argparse.ArgumentParser(description='IP Geolocation Script')
    parser.add_argument('-L', '--input', required=True, help='Path to the input file containing IP addresses (one per line)')
    parser.add_argument('-O', '--output', required=True, help='Path to the output Excel file')
    parser.add_argument('-S', '--sleep', type=float, default=0.5, help='Sleep time between API requests to respect rate limits (default: 0.5 seconds)')
    return parser.parse_args()

def read_ip_addresses(file_path):
    try:
        with open(file_path, 'r') as file:
            ips = [line.strip() for line in file if line.strip()]
        return ips
    except Exception as e:
        print(f"Error reading IP addresses from {file_path}: {e}")
        sys.exit(1)

def get_geolocation(ip):
    """
    Retrieves geolocation data for a given IP address using ip-api.com.

    Returns a dictionary with the results or None if failed.
    """
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data['status'] == 'success':
            return {
                'IP': ip,
                'Country': data.get('country', ''),
                'Region': data.get('regionName', ''),
                'City': data.get('city', ''),
                'ZIP': data.get('zip', ''),
                'Latitude': data.get('lat', ''),
                'Longitude': data.get('lon', ''),
                'Timezone': data.get('timezone', ''),
                'ISP': data.get('isp', ''),
                'Organization': data.get('org', ''),
                'AS': data.get('as', '')
            }
        else:
            return {
                'IP': ip,
                'Country': '',
                'Region': '',
                'City': '',
                'ZIP': '',
                'Latitude': '',
                'Longitude': '',
                'Timezone': '',
                'ISP': '',
                'Organization': '',
                'AS': '',
                'Error': data.get('message', 'Unknown Error')
            }
    except Exception as e:
        return {
            'IP': ip,
            'Country': '',
            'Region': '',
            'City': '',
            'ZIP': '',
            'Latitude': '',
            'Longitude': '',
            'Timezone': '',
            'ISP': '',
            'Organization': '',
            'AS': '',
            'Error': str(e)
        }

def main():
    args = parse_arguments()
    ip_list = read_ip_addresses(args.input)
    
    if not ip_list:
        print("No IP addresses found in the input file.")
        sys.exit(1)
    
    results = []
    total_ips = len(ip_list)
    print(f"Starting geolocation for {total_ips} IP addresses...\n")
    
    for idx, ip in enumerate(ip_list, start=1):
        print(f"Processing {idx}/{total_ips}: {ip}")
        geo_data = get_geolocation(ip)
        results.append(geo_data)
        # Sleep to respect rate limits (ip-api.com allows 45 requests per minute)
        time.sleep(args.sleep)
    
    # Create a DataFrame
    df = pd.DataFrame(results)
    
    # Handle errors by placing them in a separate column or marking them
    if 'Error' in df.columns:
        df_errors = df[df['Error'].notna() & (df['Error'] != '')]
        if not df_errors.empty:
            print("\nSome IP addresses could not be geolocated:")
            print(df_errors[['IP', 'Error']])
    
    # Export to Excel
    try:
        df.to_excel(args.output, index=False)
        print(f"\nGeolocation data successfully written to {args.output}")
    except Exception as e:
        print(f"Error writing to Excel file {args.output}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

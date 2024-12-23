#!/usr/bin/env python3

import argparse
import requests
import pandas as pd
import sys
import time

def parse_arguments():
    parser = argparse.ArgumentParser(description='IP Geolocation Script with API Key')
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

def get_geolocation(ip, api_key):
    """
    Retrieves geolocation data for a given IP address using an API key.

    Returns a dictionary with the results or None if failed.
    """
    url = f"https://ipinfo.io/{ip}?token={api_key}"  # Replace with your API endpoint
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            privacy = data.get('privacy', {})
            return {
                'IP': ip,
                'Hostname': data.get('hostname', ''),
                'City': data.get('city', ''),
                'Region': data.get('region', ''),
                'Country': data.get('country', ''),
                'Location': data.get('loc', ''),
                'Org': data.get('org', ''),
                'Postal': data.get('postal', ''),
                'Timezone': data.get('timezone', ''),
                'ASN': data.get('asn', {}).get('asn', ''),
                'ISP': data.get('asn', {}).get('name', ''),
                'Privacy_VPN': privacy.get('vpn', False),
                'Privacy_Proxy': privacy.get('proxy', False),
                'Privacy_Tor': privacy.get('tor', False),
                'Privacy_Relay': privacy.get('relay', False),
                'Privacy_Hosting': privacy.get('hosting', False),
                'Privacy_Service': privacy.get('service', ''),
                'Abuse Contact': data.get('abuse', {}),
            }
        else:
            return {
                'IP': ip,
                'Error': f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        return {
            'IP': ip,
            'Error': str(e)
        }

def main():
    api_key = "4d0893f3feb9d9"  # Replace with your actual API key
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
        geo_data = get_geolocation(ip, api_key)
        results.append(geo_data)
        # Sleep to respect rate limits
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

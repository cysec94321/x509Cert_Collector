# Handles TLS/SSL connections
import ssl
import socket
# For accessing x509 certificate details
from OpenSSL import crypto
# For writing to CSV file
import csv
# For converting datetime output to a human readable format
from datetime import datetime
import pandas as pd
from tqdm import tqdm

df = pd.read_csv('websites.csv')
urls = df.iloc[:, 0].tolist()
#urls = ["google.com", "github.com", "coles.com.au", "woolworths.com.au", "deakin.edu.au", "stepfwdit.com.au"]  
# Output file
csv_file = 'tls_certificate_details.csv'

# Check if certificate has expired
def has_expired(cert):
    
    if cert.has_expired():
        return str("Yes")
    else:
        return str("No")
    
# Function returns dictionary of certificate details
def get_tls_certificate_details(url):
    
    # Establish a secure SSL context (config for managing TLS commnications settings.)
    context = ssl.create_default_context()

    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
    
    # Timeout for the connection in seconds
    conn.settimeout(10.0)
    
    try:
        # Connect to the server to get the certificate
        # 443 for HTTPS Port
        conn.connect((url, 443))
        # Get the certificate in DER format
        der_cert = conn.getpeercert(True)
        # Load DER format certificate into X509 object/structure using OpenSSL
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

        # Access the subject and issuer details directly using X509Name attributes
        # extract attributes from subject + issuer objects instead of via whole cert, to negate the need for Chained indexing to access specific attributes.
        subject = x509.get_subject() 
        issuer = x509.get_issuer() 

        # Extract the certificate details into a dictionary
        # Key | attribute value + formatting
        details = {
            # Access desired attributes from the subject object
            # ' ' is default value if the attribute is not present
            'Common Name': getattr(subject, 'CN', ''),
            'Organization': getattr(subject, 'O', ''),
            
            # get + convert serial to hex format
            'Serial Number': (x509.get_serial_number()),

            # Access desired attributes from the issuer object
            'Issuer Common Name': getattr(issuer, 'CN', ''),
            'Issuer Organization': getattr(issuer, 'O', ''),

            # Convert to datetime object and then into a human readable string
            'Valid From': datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S'), 
            'Valid To': datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S'),
              
            'Version': x509.get_version(), 
            # Returns string based on has_expired function

            'Expired': has_expired(x509),

            'Country': getattr(subject, 'C', ''),  
              
            'Algorithm': x509.get_signature_algorithm().decode('utf-8'),            

            'Fingerprint': x509.digest('sha256').decode('utf-8'),   
        }

    # Handle any exceptions that occur during the connection
    except Exception as e:
        print(f"Error retrieving certificate for {url}: {e}")
        details = {}
    
    # Close the connection
    finally:
        conn.close()

    return details

# Open the CSV file in write mode, also ensures that newline characters in the data don't get changed (important for csv files)
with open(csv_file, mode='w', newline='') as file:
    
    # Define the column names for the CSV (aligning with dictionary keys)
    fieldnames = ['URL', 'Common Name', 'Organization', 'Serial Number', 'Issuer Common Name', 'Issuer Organization', 'Valid From', 'Valid To', 'Fingerprint', 'Version', 'Expired', 'Algorithm', 'Country']
    
    # Create a CSV DictWriter object, which maps the dictionaries onto the rows in the CSV'
    #fieldnames = list of keys
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    
    # Write the column names as the header row in the CSV
    writer.writeheader()
    detail_count = 1
    # Iterate over each URL in the list
    for url in urls:
        # Use the previously defined function to get certificate details for the URL
        details = get_tls_certificate_details(url)
        
        # Check if the details were successfully retrieved
        if details:
            # Write the details as a new row in the CSV, prefixing with the URL
            writer.writerow({'URL': url, **details})
            print(f"[{detail_count}] TLS certificate details for {url} have been saved to {csv_file}")
            detail_count += 1

print(f"TLS certificate details have been saved to {csv_file}")
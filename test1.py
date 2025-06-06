import boto3
import csv
from datetime import datetime

def scan_s3_buckets():
    s3 = boto3.client('s3')
    results = []

    try:
        response = s3.list_buckets()
    except Exception as e:
        print(f"[❌] Error connecting to AWS: {e}")
        return

    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        status = "PRIVATE"

        # Check ACL
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant):
                    status = "PUBLIC via ACL"
                    break
        except:
            status = "ERROR (ACL)"

        # Check Bucket Policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            if '"Principal":"*"' in policy['Policy'].replace(" ", ""):
                status = "PUBLIC via Policy"
        except:
            pass

        
        results.append([bucket_name, status])

    # For Timing
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"s3_results_{timestamp}.csv"


    # Save to CSV
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Bucket Name", "Status"])
        writer.writerows(results)

    print("\n✅ Scan complete. Results saved to 's3_results.csv'.")

if __name__ == "__main__":
    scan_s3_buckets()

import boto3
import boto3.session
from botocore.exceptions import ClientError
import csv
from datetime import datetime
from getpass import getpass

print("WELCOME TO AWS☁️ AUDITING TOOL🛠️")
def get_s3_client():
    try:
        user_input = input("IAM User Selection (\"Manual Entry\" = M) or (\"AWS Profiles\" = P) :")
        if user_input == "M" :
            access_key = input("Enter AWS Access Key:").strip()
            secret_key = getpass("Enter AWS Secret Key:").strip()
            if not access_key or not secret_key:
                print("Keys cannot be empitied!!")
                exit()
            session = boto3.Session(
            aws_access_key_id= access_key,
            aws_secret_access_key = secret_key
            )
            return session.client("s3")
        elif user_input == "P":
            name = input("Enter the AWS Profile for S3 Auditing:").strip()
            if not name:
                print("Profile cannot be empty!!")
                exit()
            session = boto3.Session(
                profile_name = name
            )
            return session.client("s3")
        else :
            print("❌ Invalid option. Please enter M or P.")
    except Exception as e:
        print(f"❌ Could not found the AWS acoount : {e}")
        exit()

def scan_s3_buckets():
    s3 = get_s3_client()
    results = []
    print("Scanning as Started ⏳")
    try:
        response = s3.list_buckets()
    except Exception as e:
        print(f"[❌] Error connecting to AWS: {e}")
        return

    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        status = "PRIVATE"
        encrypt_status = "NO ENCRYPTION"
        version_status = "UNKNOWN"
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
        
        #Checking Encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            encrypt_status = "ENCRYPTION ENABLED"
        except s3.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                encrypt_status = "NO ENCRYPTION"
            else:
                encrypt_status = f"ERROR: {e.response['Error']['Code']}"
        except Exception as e:
            encrypt_status = f"ERROR: {str(e)}"

        #Checking Versioning
        try : 
            vn = s3.get_bucket_versioning(Bucket = bucket_name)
            if 'Status' in vn and vn['Status'] == 'Enabled':
                version_status = 'Version Enabled'
            elif 'Status' in vn and vn['Status'] == 'Suspended':
                version_status = 'Version Suspended'
            else:
                version_status = 'Version Not Configured'
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == 'AccessDenied':
                version_status = "ERROR (Versioning: Access Denied)"
            else:
                version_status = f"ERROR (Versioning: {error_code})"
        except Exception as e:
            version_status = f"ERROR (Versioning: {type(e).__name__})"
        
        results.append([bucket_name, status , encrypt_status,version_status])

    # For Timing
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"s3_results_{timestamp}.csv"


    # Save to CSV
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Bucket Name", "Status", "Encryption" , "Versioning"])
        writer.writerows(results)

    print("\n✅ Scan complete. Results saved to 's3_results.csv'.")

if __name__ == "__main__":
    scan_s3_buckets()

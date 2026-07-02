import json
import boto3
import uuid
import gzip
import urllib.parse
from datetime import datetime

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
bedrock = boto3.client("bedrock-runtime")
sns = boto3.client("sns")

TABLE_NAME = "__________________"
MODEL_ID = "amazon.nova-micro-v1:0"
SNS_TOPIC_ARN = "_________________"

table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    try:
        processed_files = 0
        findings_created = 0

        for record in event.get("Records", []):
            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

            if not key.endswith(".json.gz"):
                continue

            records = read_cloudtrail_file(bucket, key)
            security_events = extract_security_events(records)

            if security_events:
                analysis = analyze_with_bedrock(security_events)

                risk_level = extract_risk_level(analysis)

                save_finding(
                    source="cloudtrail_s3",
                    raw_log_sample=json.dumps(security_events[:10], indent=2),
                    ai_analysis=analysis,
                    s3_bucket=bucket,
                    s3_key=key
                )

       
                if risk_level in ["HIGH", "CRITICAL"]:
                    send_sns_alert(
                        risk_level=risk_level,
                        analysis=analysis,
                        bucket=bucket,
                        key=key
                    )

                findings_created += 1

            processed_files += 1

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "CloudTrail processing complete",
                "processed_files": processed_files,
                "findings_created": findings_created
            })
        }

    except Exception as e:
        print("ERROR:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }


def read_cloudtrail_file(bucket, key):
    obj = s3.get_object(Bucket=bucket, Key=key)
    compressed = obj["Body"].read()
    decompressed = gzip.decompress(compressed).decode("utf-8")

    data = json.loads(decompressed)
    return data.get("Records", [])


def extract_security_events(records):

    important_events = {
        "ConsoleLogin",
        "CreateAccessKey",
        "DeleteAccessKey",
        "AttachUserPolicy",
        "PutBucketPolicy",
        "StopLogging",
        "DeleteTrail",
        "AuthorizeSecurityGroupIngress",
        "DisableMFADevice"
    }

    suspicious_errors = {
        "AccessDenied",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation"
    }

    events = []

    for r in records:
        event_name = r.get("eventName", "")
        error_code = r.get("errorCode", "")

        if event_name in important_events or error_code in suspicious_errors:

            events.append({
                "time": r.get("eventTime"),
                "event": event_name,
                "user": r.get("userIdentity", {}).get("arn", "unknown"),
                "ip": r.get("sourceIPAddress", "unknown"),
                "region": r.get("awsRegion", "unknown"),
                "error": error_code
            })

    return events


def analyze_with_bedrock(events):

    prompt = f"""
You are a cloud security analyst.

Analyze this AWS activity and return:

Risk Level (LOW, MEDIUM, HIGH, CRITICAL)
Summary
Key Findings
Recommendations

Data:
{json.dumps(events, indent=2)}
"""

    try:
        response = bedrock.converse(
            modelId=MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": prompt}]
                }
            ],
            inferenceConfig={
                "maxTokens": 400,
                "temperature": 0.1
            }
        )

        text = response["output"]["message"]["content"][0]["text"]

        return text

    except Exception as e:
        print("Bedrock error:", str(e))
        return fallback_analysis(events)


def extract_risk_level(text):

    text = text.upper()

    if "CRITICAL" in text:
        return "CRITICAL"
    if "HIGH" in text:
        return "HIGH"
    if "MEDIUM" in text:
        return "MEDIUM"

    return "LOW"


def fallback_analysis(events):

    return f"""
Risk Level: MEDIUM

Summary:
CloudTrail activity was detected but could not be fully analyzed by AI.

Events Count: {len(events)}

Recommendations:
Review IAM activity, login attempts, and permission changes manually.
"""

def save_finding(source, raw_log_sample, ai_analysis, s3_bucket, s3_key):

    finding_id = str(uuid.uuid4())

    table.put_item(Item={
        "finding_id": finding_id,
        "timestamp": datetime.utcnow().isoformat(),
        "source": source,
        "raw_log_sample": raw_log_sample,
        "ai_analysis": ai_analysis,
        "s3_bucket": s3_bucket,
        "s3_key": s3_key
    })

    return finding_id


def send_sns_alert(risk_level, analysis, bucket, key):

    message = f"""
🚨 AWS SECURITY ALERT 🚨

Risk Level: {risk_level}

S3 Bucket: {bucket}
Log File: {key}

AI Analysis:
{analysis}

Action Required:
Review AWS CloudTrail activity immediately.
"""

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"AWS Security Alert - {risk_level}",
        Message=message
    )

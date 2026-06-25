# AI-Security-Monitor

The AI Security Monitor is a serverless cloud security application that monitors AWS account activity, automatically analyzes CloudTrail logs using artificial intelligence, and stores security findings. Rather than relying on manual log reviews, the application detects security-relevant events as they occur and provides AI-generated summaries and risk assessments.

This project was designed and deployed using AWS cloud-native services with a focus on automation, serverless architecture, and cloud security best practices. The solution leverages event-driven architecture to automatically process AWS CloudTrail logs without requiring manual intervention.

# Project Goals

- Build an automated cloud security monitoring solution
- Implement a serverless event-driven architecture
- Automatically analyze AWS CloudTrail logs using AI
- Detect security-relevant AWS account activity
- Store security findings for future investigation
- Demonstrate cloud security, automation, and AI integration

# Architecture 
<img width="814" height="196" alt="Screenshot 2026-06-25 at 12 28 03 PM" src="https://github.com/user-attachments/assets/f67bc101-adcf-40fb-877f-8ae6e9e9cf4d" />

AWS Infrastructure

- Amazon CloudTrail
- Amazon S3 (Private Log Storage)
- AWS Lambda
- Amazon Bedrock
- Amazon DynamoDB
- Amazon IAM
- Amazon CloudWatch

Every action performed within the AWS account such as IAM changes, console logins, permission modifications, or security group updates is recorded by AWS CloudTrail.

CloudTrail continuously delivers log files to a private Amazon S3 bucket. Whenever a new log file is created, Amazon S3 automatically triggers an AWS Lambda function using an S3 Event Notification.

The Lambda function downloads the CloudTrail log file.

The extracted security events are then sent to Amazon Bedrock, where the Amazon Nova Micro foundation model analyzes the activity and generates an AI-assisted security assessment that includes:

Risk Level
Executive Summary
Notable Security Patterns
Recommended Administrative Actions

Finally, both the original security events and the AI-generated analysis are stored in Amazon DynamoDB, creating a searchable repository of findings.

# Lessons Learned

During this project, I gained hands-on experience building an automated cloud security monitoring solution using AWS serverless services. I learned how CloudTrail records AWS account activity, how Amazon S3 event notifications can trigger automated workflows, and how AWS Lambda can process security events without requiring infrastructure.

I also gained experience integrating Amazon Bedrock into a security-focused application, allowing AI to interpret CloudTrail logs and generate security assessments. 

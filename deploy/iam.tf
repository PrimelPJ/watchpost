# The Lambda role gets only what the fixes need.

resource "aws_iam_role" "lambda" {
  name               = "${var.name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.name}-permissions"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid = "S3PublicAccessBlock"
    actions = [
      "s3:GetBucketTagging",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
    ]
    resources = ["arn:${local.partition}:s3:::*"]
  }

  statement {
    sid       = "Ec2Read"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:DescribeInstances"]
    resources = ["*"]
  }

  statement {
    sid = "Ec2Fix"
    actions = [
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateSecurityGroup",
      "ec2:ModifyInstanceAttribute",
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "IamRead"
    actions   = ["iam:ListUserTags", "iam:ListAccessKeys"]
    resources = ["arn:${local.partition}:iam::${local.account}:user/*"]
  }

  statement {
    sid       = "IamTurnOffKeys"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:${local.partition}:iam::${local.account}:user/*"]
  }

  # watchpost may only detach this one policy, nothing else.
  statement {
    sid       = "IamDetachAdminOnly"
    actions   = ["iam:DetachUserPolicy"]
    resources = ["arn:${local.partition}:iam::${local.account}:user/*"]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = ["arn:${local.partition}:iam::aws:policy/AdministratorAccess"]
    }
  }

  statement {
    sid       = "CloudTrail"
    actions   = ["cloudtrail:GetTrailStatus", "cloudtrail:DescribeTrails", "cloudtrail:StartLogging"]
    resources = ["*"]
  }

  statement {
    sid       = "Alerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "AlertsKey"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = [aws_kms_key.alerts.arn]
  }

  statement {
    sid       = "FailedQueue"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.failed.arn]
  }
}

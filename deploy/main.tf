data "aws_caller_identity" "me" {}
data "aws_partition" "current" {}

locals {
  account   = data.aws_caller_identity.me.account_id
  partition = data.aws_partition.current.partition
  tags      = merge({ app = var.name }, var.tags)
}

# ---------- Lambda code ----------

data "archive_file" "code" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/watchpost.zip"
  excludes    = ["watchpost.egg-info"]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_lambda_function" "watchpost" {
  function_name    = var.name
  description      = "Catches risky AWS changes and fixes or reports them."
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "watchpost.handler.lambda_handler"
  filename         = data.archive_file.code.output_path
  source_code_hash = data.archive_file.code.output_base64sha256
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      WATCHPOST_MODE                   = var.mode
      WATCHPOST_TOPIC_ARN              = aws_sns_topic.alerts.arn
      WATCHPOST_DISABLED               = join(",", var.disabled_responders)
      WATCHPOST_GUARDDUTY_MIN_SEVERITY = tostring(var.guardduty_min_severity)
    }
  }

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.lambda]
}

# Retry a failed run once, then send the event to the dead letter queue so it is not lost.
resource "aws_lambda_function_event_invoke_config" "watchpost" {
  function_name          = aws_lambda_function.watchpost.function_name
  maximum_retry_attempts = 1

  destination_config {
    on_failure {
      destination = aws_sqs_queue.failed.arn
    }
  }
}

resource "aws_sqs_queue" "failed" {
  name                      = "${var.name}-failed"
  message_retention_seconds = 1209600 # 14 days
  sqs_managed_sse_enabled   = true
  tags                      = local.tags
}

# ---------- Alerts ----------

# A customer managed key, because CloudWatch alarms cannot publish to a topic
# that uses the default AWS managed SNS key.
resource "aws_kms_key" "alerts" {
  description         = "${var.name} alert topic"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.key.json
  tags                = local.tags
}

resource "aws_kms_alias" "alerts" {
  name          = "alias/${var.name}-alerts"
  target_key_id = aws_kms_key.alerts.key_id
}

data "aws_iam_policy_document" "key" {
  statement {
    sid       = "AccountAdmins"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account}:root"]
    }
  }

  statement {
    sid       = "CloudWatchAlarms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = aws_kms_key.alerts.arn
  tags              = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Tell us if watchpost itself breaks.
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  alarm_description   = "watchpost failed to handle an event. Check its logs and the ${var.name}-failed queue."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.watchpost.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

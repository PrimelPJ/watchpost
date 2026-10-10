# EventBridge rules: which events wake watchpost up.
# CloudTrail API events need a CloudTrail trail that logs management events.

locals {
  api_call = "AWS API Call via CloudTrail"

  regional_rules = {
    s3-public = {
      source        = ["aws.s3"]
      "detail-type" = [local.api_call]
      detail = {
        eventSource = ["s3.amazonaws.com"]
        eventName   = ["PutBucketAcl", "PutBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock"]
      }
    }
    sg-open = {
      source        = ["aws.ec2"]
      "detail-type" = [local.api_call]
      detail = {
        eventSource = ["ec2.amazonaws.com"]
        eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
      }
    }
    cloudtrail-off = {
      source        = ["aws.cloudtrail"]
      "detail-type" = [local.api_call]
      detail = {
        eventSource = ["cloudtrail.amazonaws.com"]
        eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail"]
      }
    }
    guardduty = {
      source        = ["aws.guardduty"]
      "detail-type" = ["GuardDuty Finding"]
      detail = {
        severity = [{ numeric = [">=", var.guardduty_min_severity] }]
      }
    }
  }

  # These only arrive in us-east-1.
  global_rules = {
    iam-admin = {
      source        = ["aws.iam"]
      "detail-type" = [local.api_call]
      detail = {
        eventSource = ["iam.amazonaws.com"]
        eventName   = ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"]
      }
    }
    root-access-key = {
      source        = ["aws.iam"]
      "detail-type" = [local.api_call]
      detail = {
        eventSource  = ["iam.amazonaws.com"]
        eventName    = ["CreateAccessKey"]
        userIdentity = { type = ["Root"] }
      }
    }
    root-sign-in = {
      source        = ["aws.signin"]
      "detail-type" = ["AWS Console Sign In via CloudTrail"]
      detail = {
        userIdentity = { type = ["Root"] }
      }
    }
  }

  rules = merge(
    local.regional_rules,
    { for name, rule in local.global_rules : name => rule if var.watch_global_events },
  )
}

resource "aws_cloudwatch_event_rule" "watch" {
  for_each      = local.rules
  name          = "${var.name}-${each.key}"
  description   = "Send ${each.key} events to watchpost"
  event_pattern = jsonencode(each.value)
  tags          = local.tags
}

resource "aws_cloudwatch_event_target" "watch" {
  for_each = local.rules
  rule     = aws_cloudwatch_event_rule.watch[each.key].name
  arn      = aws_lambda_function.watchpost.arn
}

resource "aws_lambda_permission" "events" {
  for_each      = local.rules
  statement_id  = "events-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.watchpost.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.watch[each.key].arn
}

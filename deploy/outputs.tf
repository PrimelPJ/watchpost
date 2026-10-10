output "function_name" {
  value = aws_lambda_function.watchpost.function_name
}

output "alert_topic_arn" {
  description = "Subscribe more people or tools (Slack, PagerDuty) to this topic."
  value       = aws_sns_topic.alerts.arn
}

output "failed_queue_url" {
  description = "Events watchpost could not handle end up here."
  value       = aws_sqs_queue.failed.url
}

output "watched_events" {
  value = sort(keys(local.rules))
}

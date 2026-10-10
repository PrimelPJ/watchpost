variable "name" {
  description = "Name used for every resource watchpost creates."
  type        = string
  default     = "watchpost"
}

variable "mode" {
  description = "\"alert\" only reports problems. \"fix\" also undoes the risky change. Start with alert."
  type        = string
  default     = "alert"

  validation {
    condition     = contains(["alert", "fix"], var.mode)
    error_message = "mode must be \"alert\" or \"fix\"."
  }
}

variable "alert_email" {
  description = "Email that gets the alerts. Leave empty to skip. AWS sends a confirm link first."
  type        = string
  default     = ""
}

variable "watch_global_events" {
  description = "IAM and console sign-in events only show up in us-east-1. Set true there, false in other regions."
  type        = bool
  default     = true
}

variable "guardduty_min_severity" {
  description = "Only act on GuardDuty findings at or above this score (7 = high)."
  type        = number
  default     = 7
}

variable "disabled_responders" {
  description = "Responders to turn off, like [\"gd_instance\"]."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "How long to keep the Lambda logs."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags added to everything."
  type        = map(string)
  default     = {}
}

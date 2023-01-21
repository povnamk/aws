locals {
  is_bucket_logs_enabled = (var.logging_bucket_name !="") || var.create_logging_bucket
  log_bucket_name  = var.logging_bucket_name == "" ? "${var.bucket_name}-logs" : var.logging_bucket
}

# Bucket Creation
resource "aws_s3_bucket" {
  count = var.create_logging_bucket ? 1 : 0
  bucket = local.log_bucket_name
  acl = "log-delivery-write"
  
  versioning {
    enabled = true
    mfa_delete = var.enable_mfa_delete
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  lifecycle_rule {
    id = var.stack_name
    enabled = true
    expiration {
      days = var.log_retention
    }
  }
  
  force_destroy = var.enable_force_destroy
  tags = var.tags
}

resource "aws_s3_bucket" "bucket" {
  bucket = var.bucket_name
  acl = length(var.grants) == 0 ? var.bucket_acl : null
  
  dynamic "grant" {
    for_each = var.grants
    content {
      id    = grant.value["id"]
      type  = grant.value["type"]
      permissions = grant.value["permissions"]
      uri = grant.value["uri"]
    }
  }
  
  dynamic "logging" {
    for_each = local.is_bucket_logs_enabled ? [1] : []
    content {
      target_bucket = local.log_bucket_name
      target_prefix = "${var.stack_name}/s3/${var.bucket_name}/"
    }
  }
  
  
  dynamic "lifecycle_rule" {
    for_each = var.object_expuration_days != 0 ? [1] :[]
    content {
      id = var.stack_name
      enabled = true
      
      expiration {
        days = var.object_expiration_days
      }
    }
  }
  
  versioning {
    enabled = true
    mfa_delelte = var.enable_mfa_delete
  }
  
  dynamic "object_lock_configuration" {
    for_each = var.enable_object_lock ? [1] :[]
    content {
      object_lock_enabled = "Enabled"
      rule {
        default_retention {
          mode = "COMPLIANCE"
          days = var.object_lock_retention
        }
      }
    }
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  
 force_destroy = var.enable_force_destroy
  tags = var.tags
  depends_on = [aws_s3_bucket.log_bucket]
}

resource "aws_s3_bucket_public_access_block" "log_public_access_block" {
  count = var.create_logging_bucket ? 1 : 0
  bucket = aws_s3_bucket.log_bucket[0].id
  
  block_public_acls= true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "bucket_public_acess_block" {
  bucket = aws_s3_bucket.bucket.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
  
}

data "aws_iam_policy_document" "secure_log_bucket_policy" {
  count = var.create_logging_bucket ? 1 : 0 
  
  statement {
    sid = "AllowSSLRequestOnly"
    actions = ["s3:*"]
    effect = "Deny"
    resources = [
      aws_s3_bucket.log_bucket[0].arn,
      "${aws_s3_bucket.log_bucket[0].arn}/*",
      ]
    principals {
      identifiers = ["*"]
      type = "AWS"
    }
  }
}

data "aws_iam_policy_document" "secure_bucket_policy" {
  override_json = var.additional_bucket_policy_json 
  
  statement {
    sid = "AllowSSLRequestOnly"
    actions = ["s3:*"]
    effect = "Deny"
    resources = [
      aws_s3_bucket.bucket[0].arn,
      "${aws_s3_bucket.bucket[0].arn}/*",
      ]
    
    condition {
      test = "Bool"
      values = ["false"]
      variable = "aws:SecureTransport"
    }
    principals {
      identifiers = ["*"]
      type = "AWS"
    }
  }
}

resource "aws_s3_bucket_policy" "attach_log_bucket_policy" {
  count = var.create_logging_bucket ? 1 : 0
  bucket = aws_s3_bucket.log_bucket[0].id
  policy = data.aws_iam_policy_document.secure_log_bucket_policy[0].json
  depends_on = [aws_s3_bucket_public_access_block.log_bucket_public_acess_block[0]]
}

resource "aws_s3_bucket_policy" "attach_bucket_policy"{
  bucket = aws_s3_bucket.id
  policy = data.aws_iam_policy_document.secure_bucket_policy.json
  depends_on = [aws_s3_bucket_public_access_block.bucket_public_access_block]
}






















































  
  
  
  
  
  
  
  
  
  
  
















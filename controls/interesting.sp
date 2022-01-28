variable "interesting_tags" {
  type        = list(string)
  description = "A list of interesting tags to check for."
}

locals {
  interesting_sql = <<EOT
    with analysis as (
      select
        arn,
        title,
        tags ?& $1 as has_interesting_tags,
        tags,
        to_jsonb($1) - array(select jsonb_object_keys(tags)) as missing_tags,
        __DIMENSIONS__
      from
        __TABLE_NAME__
    )
    select
      arn as resource,
      title,
      tags -> 'Name' as name,
      tags -> 'Environnment' as nn_environ,
      tags -> 'Environment' as environment,
      tags -> 'TerraformWorkspace' as terraform_workspace,
      tags -> 'elasticbeanstalk:environment-name' as bean_environ,
      case
        when has_interesting_tags then 'ok'
        else 'alarm'
      end as status,
      case
        when has_interesting_tags then title || ' has all interesting tags.'
        else title || ' is missing tags: ' || array_to_string(array(select jsonb_array_elements_text(missing_tags)), ', ') || '.'
      end as reason,
      __DIMENSIONS__
    from
      analysis
  EOT
}

locals {
  interesting_sql_account = replace(local.interesting_sql, "__DIMENSIONS__", "account_id")
  interesting_sql_region  = replace(local.interesting_sql, "__DIMENSIONS__", "region, account_id")
}

benchmark "interesting" {
  title       = "Interesting"
  description = "Custom report for Informed. For all resources, get the title tags: Name Environment Environnment TerraformWorkspace elasticbeanstal:environment-name. This can then be used by other tools to synthesize an Environment assingment"
  children = [
    control.accessanalyzer_analyzer_interesting,
    control.api_gateway_stage_interesting,
    control.cloudfront_distribution_interesting,
    control.cloudtrail_trail_interesting,
    control.cloudwatch_alarm_interesting,
    control.cloudwatch_log_group_interesting,
    control.codebuild_project_interesting,
    control.codecommit_repository_interesting,
    control.codepipeline_pipeline_interesting,
    control.config_rule_interesting,
    control.dax_cluster_interesting,
    control.directory_service_directory_interesting,
    control.dms_replication_instance_interesting,
    control.dynamodb_table_interesting,
    control.ebs_snapshot_interesting,
    control.ebs_volume_interesting,
    control.ec2_application_load_balancer_interesting,
    control.ec2_classic_load_balancer_interesting,
    control.ec2_gateway_load_balancer_interesting,
    control.ec2_instance_interesting,
    control.ec2_network_load_balancer_interesting,
    control.ec2_reserved_instance_interesting,
    control.ecr_repository_interesting,
    control.ecs_container_instance_interesting,
    control.ecs_service_interesting,
    control.efs_file_system_interesting,
    control.eks_addon_interesting,
    control.eks_cluster_interesting,
    control.eks_identity_provider_config_interesting,
    control.elastic_beanstalk_application_interesting,
    control.elastic_beanstalk_environment_interesting,
    control.elasticache_cluster_interesting,
    control.elasticsearch_domain_interesting,
    control.eventbridge_rule_interesting,
    control.guardduty_detector_interesting,
    control.iam_role_interesting,
    control.iam_server_certificate_interesting,
    control.iam_user_interesting,
    control.inspector_assessment_template_interesting,
    control.kinesis_firehose_delivery_stream_interesting,
    control.kms_key_interesting,
    control.lambda_function_interesting,
    control.rds_db_cluster_interesting,
    control.rds_db_cluster_parameter_group_interesting,
    control.rds_db_cluster_snapshot_interesting,
    control.rds_db_instance_interesting,
    control.rds_db_option_group_interesting,
    control.rds_db_parameter_group_interesting,
    control.rds_db_snapshot_interesting,
    control.rds_db_subnet_group_interesting,
    control.redshift_cluster_interesting,
    control.route53_domain_interesting,
    control.route53_resolver_endpoint_interesting,
    control.s3_bucket_interesting,
    control.sagemaker_endpoint_configuration_interesting,
    control.sagemaker_model_interesting,
    control.sagemaker_notebook_instance_interesting,
    control.sagemaker_training_job_interesting,
    control.secretsmanager_secret_interesting,
    control.ssm_parameter_interesting,
    control.tagging_resource_interesting,
    control.vpc_interesting,
    control.vpc_eip_interesting,
    control.vpc_nat_gateway_interesting,
    control.vpc_network_acl_interesting,
    control.vpc_security_group_interesting,
    control.vpc_vpn_connection_interesting,
    control.wafv2_ip_set_interesting,
    control.wafv2_regex_pattern_set_interesting,
    control.wafv2_rule_group_interesting,
    control.wafv2_web_acl_interesting
  ]
}

control "accessanalyzer_analyzer_interesting" {
  title       = "Access Analyzer analyzers should have interesting tags"
  description = "Check if Access Analyzer analyzers have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_accessanalyzer_analyzer")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "api_gateway_stage_interesting" {
  title       = "API Gateway stages should have interesting tags"
  description = "Check if API Gateway stages have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_api_gateway_stage")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "cloudfront_distribution_interesting" {
  title       = "CloudFront distributions should have interesting tags"
  description = "Check if CloudFront distributions have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_cloudfront_distribution")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "cloudtrail_trail_interesting" {
  title       = "CloudTrail trails should have interesting tags"
  description = "Check if CloudTrail trails have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_cloudtrail_trail")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "cloudwatch_alarm_interesting" {
  title       = "CloudWatch alarms should have interesting tags"
  description = "Check if CloudWatch alarms have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_cloudwatch_alarm")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "cloudwatch_log_group_interesting" {
  title       = "CloudWatch log groups should have interesting tags"
  description = "Check if CloudWatch log groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_cloudwatch_log_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "codebuild_project_interesting" {
  title       = "CodeBuild projects should have interesting tags"
  description = "Check if CodeBuild projects have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_codebuild_project")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "codecommit_repository_interesting" {
  title       = "CodeCommit repositories should have interesting tags"
  description = "Check if CodeCommit repositories have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_codecommit_repository")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "codepipeline_pipeline_interesting" {
  title       = "CodePipeline pipelines should have interesting tags"
  description = "Check if CodePipeline pipelines have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_codepipeline_pipeline")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "config_rule_interesting" {
  title       = "Config rules should have interesting tags"
  description = "Check if Config rules have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_config_rule")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "dax_cluster_interesting" {
  title       = "DAX clusters should have interesting tags"
  description = "Check if DAX clusters have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_dax_cluster")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "directory_service_directory_interesting" {
  title       = "Directory Service directories should have interesting tags"
  description = "Check if Directory Service directories have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_directory_service_directory")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "dms_replication_instance_interesting" {
  title       = "DMS replication instances should have interesting tags"
  description = "Check if Dms replication instances have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_dms_replication_instance")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "dynamodb_table_interesting" {
  title       = "DynamoDB tables should have interesting tags"
  description = "Check if DynamoDB tables have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_dynamodb_table")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ebs_snapshot_interesting" {
  title       = "EBS snapshots should have interesting tags"
  description = "Check if EBS snapshots have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ebs_snapshot")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ebs_volume_interesting" {
  title       = "EBS volumes should have interesting tags"
  description = "Check if EBS volumes have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ebs_volume")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ec2_application_load_balancer_interesting" {
  title       = "EC2 application load balancers should have interesting tags"
  description = "Check if EC2 application load balancers have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ec2_application_load_balancer")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ec2_classic_load_balancer_interesting" {
  title       = "EC2 classic load balancers should have interesting tags"
  description = "Check if EC2 classic load balancers have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ec2_classic_load_balancer")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ec2_gateway_load_balancer_interesting" {
  title       = "EC2 gateway load balancers should have interesting tags"
  description = "Check if EC2 gateway load balancers have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ec2_gateway_load_balancer")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ec2_instance_interesting" {
  title       = "EC2 instances should have interesting tags"
  description = "Check if EC2 instances have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ec2_instance")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ec2_network_load_balancer_interesting" {
  title       = "EC2 network load balancers should have interesting tags"
  description = "Check if EC2 network load balancers have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ec2_network_load_balancer")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ec2_reserved_instance_interesting" {
  title       = "EC2 reserved instances should have interesting tags"
  description = "Check if EC2 reserved instances have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ec2_reserved_instance")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ecr_repository_interesting" {
  title       = "ECR repositories should have interesting tags"
  description = "Check if ECR repositories have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ecr_repository")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ecs_container_instance_interesting" {
  title       = "ECS container instances should have interesting tags"
  description = "Check if ECS container instances have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ecs_container_instance")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ecs_service_interesting" {
  title       = "ECS services should have interesting tags"
  description = "Check if ECS services have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ecs_service")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "efs_file_system_interesting" {
  title       = "EFS file systems should have interesting tags"
  description = "Check if EFS file systems have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_efs_file_system")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "eks_addon_interesting" {
  title       = "EKS addons should have interesting tags"
  description = "Check if EKS addons have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_eks_addon")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "eks_cluster_interesting" {
  title       = "EKS clusters should have interesting tags"
  description = "Check if EKS clusters have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_eks_cluster")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "eks_identity_provider_config_interesting" {
  title       = "EKS identity provider configs should have interesting tags"
  description = "Check if EKS identity provider configs have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_eks_identity_provider_config")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "elastic_beanstalk_application_interesting" {
  title       = "Elastic beanstalk applications should have interesting tags"
  description = "Check if Elastic beanstalk applications have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_elastic_beanstalk_application")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "elastic_beanstalk_environment_interesting" {
  title       = "Elastic beanstalk environments should have interesting tags"
  description = "Check if Elastic beanstalk environments have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_elastic_beanstalk_environment")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "elasticache_cluster_interesting" {
  title       = "ElastiCache clusters should have interesting tags"
  description = "Check if ElastiCache clusters have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_elasticache_cluster")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "elasticsearch_domain_interesting" {
  title       = "ElasticSearch domains should have interesting tags"
  description = "Check if ElasticSearch domains have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_elasticsearch_domain")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "eventbridge_rule_interesting" {
  title       = "EventBridge rules should have interesting tags"
  description = "Check if EventBridge rules have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_eventbridge_rule")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "guardduty_detector_interesting" {
  title       = "GuardDuty detectors should have interesting tags"
  description = "Check if GuardDuty detectors have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_guardduty_detector")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "iam_role_interesting" {
  title       = "IAM roles should have interesting tags"
  description = "Check if IAM roles have interesting tags."
  sql         = replace(local.interesting_sql_account, "__TABLE_NAME__", "aws_iam_role")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "iam_server_certificate_interesting" {
  title       = "IAM server certificates should have interesting tags"
  description = "Check if IAM server certificates have interesting tags."
  sql         = replace(local.interesting_sql_account, "__TABLE_NAME__", "aws_iam_server_certificate")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "iam_user_interesting" {
  title       = "IAM users should have interesting tags"
  description = "Check if IAM users have interesting tags."
  sql         = replace(local.interesting_sql_account, "__TABLE_NAME__", "aws_iam_user")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "inspector_assessment_template_interesting" {
  title       = "Inspector assessment templates should have interesting tags"
  description = "Check if Inspector assessment templates have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_inspector_assessment_template")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "kinesis_firehose_delivery_stream_interesting" {
  title       = "Kinesis firehose delivery streams should have interesting tags"
  description = "Check if Kinesis firehose delivery streams have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_kinesis_firehose_delivery_stream")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "kms_key_interesting" {
  title       = "KMS keys should have interesting tags"
  description = "Check if KMS keys have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_kms_key")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "lambda_function_interesting" {
  title       = "Lambda functions should have interesting tags"
  description = "Check if Lambda functions have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_lambda_function")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_cluster_interesting" {
  title       = "RDS DB clusters should have interesting tags"
  description = "Check if RDS DB clusters have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_cluster")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_cluster_parameter_group_interesting" {
  title       = "RDS DB cluster parameter groups should have interesting tags"
  description = "Check if RDS DB cluster parameter groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_cluster_parameter_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_cluster_snapshot_interesting" {
  title       = "RDS DB cluster snapshots should have interesting tags"
  description = "Check if RDS DB cluster snapshots have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_cluster_snapshot")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_instance_interesting" {
  title       = "RDS DB instances should have interesting tags"
  description = "Check if RDS DB instances have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_instance")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_option_group_interesting" {
  title       = "RDS DB option groups should have interesting tags"
  description = "Check if RDS DB option groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_option_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_parameter_group_interesting" {
  title       = "RDS DB parameter groups should have interesting tags"
  description = "Check if RDS DB parameter groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_parameter_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_snapshot_interesting" {
  title       = "RDS DB snapshots should have interesting tags"
  description = "Check if RDS DB snapshots have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_snapshot")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "rds_db_subnet_group_interesting" {
  title       = "RDS DB subnet groups should have interesting tags"
  description = "Check if RDS DB subnet groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_rds_db_subnet_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "redshift_cluster_interesting" {
  title       = "Redshift clusters should have interesting tags"
  description = "Check if Redshift clusters have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_redshift_cluster")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "route53_domain_interesting" {
  title       = "Route53 domains should have interesting tags"
  description = "Check if Route53 domains have interesting tags."
  sql         = replace(local.interesting_sql_account, "__TABLE_NAME__", "aws_route53_domain")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "route53_resolver_endpoint_interesting" {
  title       = "Route 53 Resolver endpoints should have interesting tags"
  description = "Check if Route 53 Resolver endpoints have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_route53_resolver_endpoint")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "s3_bucket_interesting" {
  title       = "S3 buckets should have interesting tags"
  description = "Check if S3 buckets have interesting tags."
  sql         = replace(local.interesting_sql_account, "__TABLE_NAME__", "aws_s3_bucket")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "sagemaker_endpoint_configuration_interesting" {
  title       = "SageMaker endpoint configurations should have interesting tags"
  description = "Check if SageMaker endpoint configurations have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_sagemaker_endpoint_configuration")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "sagemaker_model_interesting" {
  title       = "SageMaker models should have interesting tags"
  description = "Check if SageMaker models have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_sagemaker_model")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "sagemaker_notebook_instance_interesting" {
  title       = "SageMaker notebook instances should have interesting tags"
  description = "Check if SageMaker notebook instances have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_sagemaker_notebook_instance")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "sagemaker_training_job_interesting" {
  title       = "SageMaker training jobs should have interesting tags"
  description = "Check if SageMaker training jobs have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_sagemaker_training_job")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "secretsmanager_secret_interesting" {
  title       = "Secrets Manager secrets should have interesting tags"
  description = "Check if Secrets Manager secrets have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_secretsmanager_secret")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "ssm_parameter_interesting" {
  title       = "SSM parameters should have interesting tags"
  description = "Check if SSM parameters have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_ssm_parameter")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "tagging_resource_interesting" {
  title       = "Tagging resources should have interesting tags"
  description = "Check if Tagging resources have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_tagging_resource")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "vpc_interesting" {
  title       = "VPCs should have interesting tags"
  description = "Check if VPCs have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_vpc")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "vpc_eip_interesting" {
  title       = "VPC elastic IP addresses should have interesting tags"
  description = "Check if VPC elastic IP addresses have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_vpc_eip")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "vpc_nat_gateway_interesting" {
  title       = "VPC NAT gateways should have interesting tags"
  description = "Check if VPC NAT gateways have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_vpc_nat_gateway")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "vpc_network_acl_interesting" {
  title       = "VPC network ACLs should have interesting tags"
  description = "Check if VPC network ACLs have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_vpc_network_acl")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "vpc_security_group_interesting" {
  title       = "VPC security groups should have interesting tags"
  description = "Check if VPC security groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_vpc_security_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "vpc_vpn_connection_interesting" {
  title       = "VPC VPN connections should have interesting tags"
  description = "Check if VPC VPN connections have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_vpc_vpn_connection")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "wafv2_ip_set_interesting" {
  title       = "WAFV2 ip sets should have interesting tags"
  description = "Check if WAFV2 ip sets have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_wafv2_ip_set")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "wafv2_regex_pattern_set_interesting" {
  title       = "WAFV2 regex pattern sets should have interesting tags"
  description = "Check if WAFV2 regex pattern sets have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_wafv2_regex_pattern_set")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "wafv2_rule_group_interesting" {
  title       = "WAFV2 rule groups should have interesting tags"
  description = "Check if WAFV2 rule groups have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_wafv2_rule_group")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

control "wafv2_web_acl_interesting" {
  title       = "WAFV2 web acls should have interesting tags"
  description = "Check if WAFV2 web acls have interesting tags."
  sql         = replace(local.interesting_sql_region, "__TABLE_NAME__", "aws_wafv2_web_acl")
  param "interesting_tags" {
    default = var.interesting_tags
  }
}

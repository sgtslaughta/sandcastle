provider "aws" {
  region = local.region
}

locals {
  name   = "ai-agent-cluster"
  region = "us-east-2"

  vpc = {
    cidr = "10.0.0.0/16"
    azs = slice(data.aws_availability_zones.available.names, 0, 3)
  }

  tags = {
    Environment = "Dev"
    ManagedBy = "Terraform"
    Project = local.name
    Repo = "https://github.com/sgtslaughta/sandcastle"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = local.name
  cidr = local.vpc.cidr

  azs             = local.vpc.azs
  private_subnets = [for k, v in local.vpc.azs : cidrsubnet(local.vpc.cidr, 4, k)]
  public_subnets  = [for k, v in local.vpc.azs : cidrsubnet(local.vpc.cidr, 8, k + 48)]

  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "karpenter.sh/discovery"          = local.name
  }

  tags = local.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"

  name                   = local.name
  kubernetes_version     = "1.36"
  endpoint_public_access = true
  enable_cluster_creator_admin_permissions = true

  # EKS Addons
  addons = {
    coredns = {}
    eks-pod-identity-agent = {
      before_compute = true
    }
    kube-proxy = {}
    vpc-cni = {
      before_compute = true
    }
    aws-ebs-csi-driver = {
      pod_identity_association = [{
        role_arn        = aws_iam_role.ebs_csi.arn
        service_account = "ebs-csi-controller-sa"
      }]
    }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  node_security_group_tags = {
    "karpenter.sh/discovery" = local.name
  }

  tags = local.tags
}

data "aws_iam_policy_document" "ebs_csi_pod_identity" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
    ]
  }
}

resource "aws_iam_role" "ebs_csi" {
  name               = "${local.name}-ebs-csi"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_pod_identity.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.ebs_csi.name
}

################################################################################
# Karpenter
################################################################################

module "karpenter" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name = module.eks.cluster_name

  enable_inline_policy            = true
  create_pod_identity_association = true

  # Attach policies needed by Karpenter nodes
  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    AmazonEBSCSIDriverPolicy     = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  }

  tags = local.tags
}

################################################################################
# Service Quotas
################################################################################

resource "aws_servicequotas_service_quota" "g_instances" {
  quota_code   = "L-DB2E81BA"
  service_code = "ec2"
  value        = 32
}

################################################################################
# Outputs
################################################################################

output "karpenter_node_role_name" {
  description = "Karpenter node IAM role name"
  value       = module.karpenter.node_iam_role_name
}

output "karpenter_queue_name" {
  description = "Karpenter SQS queue name"
  value       = module.karpenter.queue_name
}
variable "vpcname" {
  type    = "string"
  default = "MyVpc"
}

variable "cidr_block_range" {
  type    = "string"
  default = "10.0.0.0/16"
}

variable "subnet1" {
  type    = "string"
  default = "Subnet1"
}

variable "region" {
  type    = "string"
  default = "us-east-1"
}

variable "subnet2" {
  type    = "string"
  default = "Subnet2"
}

variable "subnet3" {
  type    = "string"
  default = "Subnet3"
}

variable "internetGateway" {
  type    = "string"
  default = "InternetGateway"
}

variable "account_num" {
  type    = "string"
  default = "746570542146"
}

variable "routetableName" {
  type    = "string"
  default = "RouteTable"
}

variable "destination_cidr_block" {
  type    = "string"
  default = "0.0.0.0/0"
}

variable "ami_id" {
  type    = "string"
  default = "ami-0e2d2c081f7e6da9a"
}

variable "key_name" {
  type    = "string"
  default = "prod_key_pair"
}

# Configure the AWS Provider
# provider "aws" {
#   version = "~> 2.0"
#   region  = "us-east-1"
# }
resource "aws_vpc" "vpc" {
  cidr_block           = "${var.cidr_block_range}"
  enable_dns_support   = true
  enable_dns_hostnames = false
  tags = {
    Name  = "${var.vpcname}"
  }
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow application ports"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    description = "Opening port 443 for HTTPS conncection"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # cidr_blocks = [aws_vpc.vpc.cidr_block]
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description = "Opening  port 22 for SSH connection"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # cidr_blocks = [aws_vpc.vpc.cidr_block]
    cidr_blocks     = ["0.0.0.0/0"]
  }
  
  ingress {
    description = "Opening port 80 for HTTP connection"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    # cidr_blocks = [aws_vpc.vpc.cidr_block]
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description = "Opening port 3000 for Node JS"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    # cidr_blocks = [aws_vpc.vpc.cidr_block]
    cidr_blocks     = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application"
  }
}

resource "aws_security_group" "database" {
  name        = "database"
  description = "Allow application to access database ports"
  vpc_id      = "${aws_vpc.vpc.id}"

  ingress {
    description = "Open port 3306"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = ["${aws_security_group.application.id}"]
    cidr_blocks     = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "subnet1" {
  vpc_id            = "${aws_vpc.vpc.id}"
  cidr_block        = "${cidrsubnet(aws_vpc.vpc.cidr_block, 4, 1)}"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"

  map_public_ip_on_launch = true
  tags = {
    Name = "${var.subnet1}" 
  }
}
resource "aws_subnet" "subnet2" {
  vpc_id                  = "${aws_vpc.vpc.id}"
  cidr_block              = "${cidrsubnet(aws_vpc.vpc.cidr_block, 4, 2)}"
  availability_zone       = "${data.aws_availability_zones.available.names[1]}"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.subnet2}" 
  }
}

resource "aws_subnet" "subnet3" {
  vpc_id                  = "${aws_vpc.vpc.id}"
  cidr_block              = "${cidrsubnet(aws_vpc.vpc.cidr_block, 4, 3)}"
  availability_zone       = "${data.aws_availability_zones.available.names[2]}"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.subnet3}"
  }
}

resource "aws_internet_gateway" "gateway" {
  vpc_id = "${aws_vpc.vpc.id}"
  tags = {
    Name = "${var.internetGateway}"
  }
}

resource "aws_route_table" "routetable" {
  vpc_id = "${aws_vpc.vpc.id}"
  route {
    cidr_block = "${var.destination_cidr_block}"
    gateway_id = "${aws_internet_gateway.gateway.id}"
  }
  tags = {
    Name = "${var.routetableName}"
  }
}

resource "aws_route_table_association" "route1" {
  subnet_id      = "${aws_subnet.subnet1.id}"
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route_table_association" "route2" {
  subnet_id      = "${aws_subnet.subnet2.id}"
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route_table_association" "route3" {
  subnet_id      = "${aws_subnet.subnet3.id}"
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_db_subnet_group" "rds_sn" {
  name       = "rds_subnet_group"
  subnet_ids = ["${aws_subnet.subnet1.id}", "${aws_subnet.subnet3.id}"]
}

resource "aws_db_instance" "rds" {
  allocated_storage      = 20
  identifier             = "csye6225-su2020"
  multi_az               = false
  db_subnet_group_name   = "${aws_db_subnet_group.rds_sn.name}"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  name                   = "csye6225"
  username               = "csye6225_su2020"
  password               = "itscloudcomputing_123"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  skip_final_snapshot    = true
  publicly_accessible    = false

}
resource "aws_s3_bucket" "s3" {

  bucket        = "webapp.darpit.chaudhryyi"
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket" "s3_code_deploy" {

  bucket        = "codedeploy.darpit.chaudharyi.me"
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_instance" "web-1" {
  ami           = "${var.ami_id}"
  key_name      = "${var.key_name}"
  instance_type = "t2.micro"
  user_data     = <<-EOF
                      #!/bin/bash -ex
                      echo export host=${aws_db_instance.rds.address} >> /etc/profile
                      echo export RDS_CONNECTION_STRING=${aws_db_instance.rds.address} >> /etc/profile
                      echo export RDS_USER_NAME=csye6225_su2020 >> /etc/profile
                      echo export RDS_PASSWORD=itscloudcomputing_123 >> /etc/profile
                      echo export RDS_DB_NAME=csye6225 >> /etc/profile
                      echo export PORT=3000 >> /etc/profile
                      echo export S3_BUCKET_NAME=webapp.darpit.chaudhryyi >> /etc/profile


  EOF
  ebs_block_device {
    device_name           = "/dev/sda1"
    volume_size           = "20"
    volume_type           = "gp2"
    delete_on_termination = "true"
  }

  tags = {
    name = "Codedeploy_ec2"
  }
  
  vpc_security_group_ids = ["${aws_security_group.application.id}"]

  associate_public_ip_address = true
  source_dest_check           = false
  subnet_id                   = "${aws_subnet.subnet1.id}"
  iam_instance_profile 		  = "${aws_iam_instance_profile.ec2_instance_profile.name}"
}


resource "aws_dynamodb_table" "csye6225" {
  name           = "csye6225"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
  	Name = "dynamodb_table"
  }
}

resource "aws_codedeploy_app" "codedeploy_app" {
  name = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "codedeploy_deployment_group" {
  app_name               = "csye6225-webapp"
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn      = "${aws_iam_role.codedeploy_service_role.arn}"

  ec2_tag_set {
    ec2_tag_filter {
      key   = "name"
      type  = "KEY_AND_VALUE"
      value = "Codedeploy_ec2"
    }
  }
  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = false
    events  = ["DEPLOYMENT_FAILURE"]
  }

}


resource "aws_iam_policy" "policy1" {
  name        = "CircleCI-Upload-To-S3"
  description = "Upload Policy for user s3  circleci"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
            "arn:aws:s3:::codedeploy.darpit.chaudharyi.me",
            "arn:aws:s3:::codedeploy.darpit.chaudharyi.me/*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "policy2" {
  name        = "CircleCI-Code-Deploy"
  description = "Access for user circleci to Instance"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:RegisterApplicationRevision",
                "codedeploy:GetApplicationRevision"
            ],
            "Resource": [
                "arn:aws:codedeploy:${var.region}:${var.account_num}:application:csye6225-webapp"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:CreateDeployment",
                "codedeploy:GetDeployment"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:GetDeploymentConfig"
            ],
            "Resource": [
                "arn:aws:codedeploy:${var.region}:${var.account_num}:deploymentconfig:CodeDeployDefault.OneAtATime",
                "arn:aws:codedeploy:${var.region}:${var.account_num}:deploymentconfig:CodeDeployDefault.HalfAtATime",
                "arn:aws:codedeploy:${var.region}:${var.account_num}:deploymentconfig:CodeDeployDefault.AllAtOnce"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "policy3" {
  name        = "circleci-ec2-ami"
  description = "User circleci access to EC2"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
      "Effect": "Allow",
      "Action" : [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource" : "*"
  }]
}
EOF
}


resource "aws_iam_policy_attachment" "circleci_attach1" {
  name  = "circleci_attach1"
  users = ["circleci"]
  groups     = ["circleci"]
  policy_arn = "${aws_iam_policy.policy1.arn}"
}

resource "aws_iam_policy_attachment" "circleci_attach2" {
  name  = "circleci_attach2"
  users = ["circleci"]
  groups     = ["circleci"]
  policy_arn = "${aws_iam_policy.policy2.arn}"
}

resource "aws_iam_policy_attachment" "circleci_attach3" {
  name  = "circleci_attach3"
  users = ["circleci"]
  groups     = ["circleci"]
  policy_arn = "${aws_iam_policy.policy3.arn}"
}


resource "aws_iam_role" "ec2_role" {
  name = "CodeDeployEC2ServiceRole"
  depends_on = ["aws_iam_role.codedeploy_service_role"]
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "ec2.amazonaws.com"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
  EOF
  
}


resource "aws_iam_policy" "ec2_role_policy1" {
  name        = "CodeDeploy-EC2-S3"
  description = "Instances read data from S3 buckets"
  depends_on = ["aws_iam_role.codedeploy_service_role"]
  policy      = <<EOF
{
     "Version": "2012-10-17",
     "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*",
                "iam:PassRole",
                "iam:ListInstanceProfiles",
                "iam:PassRole"
            ],
            "Effect": "Allow",
            "Resource": [
              "arn:aws:s3:::codedeploy.darpit.chaudharyi.me",
              "arn:aws:s3:::codedeploy.darpit.chaudharyi.me/*",
              "arn:aws:iam::${var.account_num}:role/CodeDeployServiceRole"
              ]
        }
    ]
}
  EOF
  
}

resource "aws_iam_policy" "ec2_role_policy2" {
  name        = "WebAppS3"
  policy = <<EOF
{ 
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::webapp.darpit.chaudhryyi",
                "arn:aws:s3:::webapp.darpit.chaudhryyi/*"
            ]
        }
    ]
}
  EOF
}

resource "aws_iam_policy_attachment" "ec2_attach1" {
  name       = "ec2attach1"
  users      = ["cicd"]
  roles      = ["${aws_iam_role.ec2_role.name}"]
  policy_arn = "${aws_iam_policy.ec2_role_policy1.arn}"
}


resource "aws_iam_policy_attachment" "ec2_attach2" {
  name       = "ec2attach2"
  users      = ["cicd"]
  roles      = ["${aws_iam_role.ec2_role.name}"]
  policy_arn = "${aws_iam_policy.ec2_role_policy2.arn}"
}



resource "aws_iam_role" "codedeploy_service_role" {
  name = "CodeDeployServiceRole"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "codedeploy.amazonaws.com"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
  EOF
}


resource "aws_iam_role_policy" "codedeploy_policy1" {
  name        = "codedeploy"
  role = aws_iam_role.codedeploy_service_role.id
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:*",
                "s3:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ]
}
  EOF
}


resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "new_instance_profile"
  role = "${aws_iam_role.ec2_role.name}"
}

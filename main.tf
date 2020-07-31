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
variable "domain_name" {
  type    = "string"
  default = "prod.darpitchaudhary.me"
}
variable "TTL" {
  type    = "string"
  default = "15"
}

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
    description = "Opening port 3000 for Node JS"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    # cidr_blocks = [aws_vpc.vpc.cidr_block]
    security_groups = ["${aws_security_group.lb_sg.id}"]
  }

  ingress {
    description = "Opening port 22 for Node JS"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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


# Loadbalancer Security Group 
resource "aws_security_group" "lb_sg" {
  name        = "aws_lb_sg"
  vpc_id      = "${aws_vpc.vpc.id}"
  description = "Allow ALB inbound traffic"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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
    # cidr_blocks     = ["0.0.0.0/0"]
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
  storage_encrypted      = true
  parameter_group_name   = "${aws_db_parameter_group.db-sslcheck.name}"
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
resource "aws_s3_bucket" "lambda" {

  bucket        = "lambda.darpit.chaudhryyi"
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

# Autoscaling group launch configuration

resource "aws_launch_configuration" "asg_launch_config" {
  image_id      = "${var.ami_id}"
  instance_type = "t2.micro"
  key_name      = "${var.key_name}"
  user_data     = <<-EOF
                      #!/bin/bash -ex
                      echo export host=${aws_db_instance.rds.address} >> /etc/profile
                      echo export RDS_CONNECTION_STRING=${aws_db_instance.rds.address} >> /etc/profile
                      echo export RDS_USER_NAME=csye6225_su2020 >> /etc/profile
                      echo export RDS_PASSWORD=itscloudcomputing_123 >> /etc/profile
                      echo export RDS_DB_NAME=csye6225 >> /etc/profile
                      echo export PORT=3000 >> /etc/profile
                      echo export S3_BUCKET_NAME=webapp.darpit.chaudhryyi >> /etc/profile
                      echo export MY_DOMAIN="${var.domain_name}" >> /etc/profile

  EOF
  iam_instance_profile        = "${aws_iam_instance_profile.ec2_instance_profile.name}"
  security_groups             = ["${aws_security_group.application.id}"]
  associate_public_ip_address = true
  depends_on                  = ["aws_db_instance.rds"]

  lifecycle {
    create_before_destroy = true
  }
}

# Configuring the load balancer

resource "aws_lb" "csye6225-lb" {
  name                       = "Application-loadbalancer"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = ["${aws_security_group.lb_sg.id}"]
  subnets                    = ["${aws_subnet.subnet2.id}", "${aws_subnet.subnet3.id}"]
  ip_address_type            = "ipv4"
  enable_deletion_protection = false

}

# target group
resource "aws_lb_target_group" "csye6225-targetgroup" {
  name     = "MyTargetGroup"
  port     = "3000"
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.vpc.id}"
  stickiness {    
    type            = "lb_cookie"    
    cookie_duration = 1800    
    enabled         = true  
  }
  health_check {
    interval            = 55
    timeout             = 45
    healthy_threshold   = 3
    unhealthy_threshold = 10
    path                = "/"
  }
}

# # Listener for LoadBalancer
# resource "aws_lb_listener" "front_end_listener" {
#   load_balancer_arn = "${aws_lb.csye6225-lb.arn}"
#   port              = "80"
#   protocol          = "HTTP"
#   default_action {
#     type             = "forward"
#     target_group_arn = "${aws_lb_target_group.csye6225-targetgroup.arn}"
#   }
# }
# Listener for LoadBalancer
resource "aws_lb_listener" "ssl" {
  load_balancer_arn = "${aws_lb.csye6225-lb.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:746570542146:certificate/7157b614-94e6-489a-abd0-321d4f8aa8e5"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.csye6225-targetgroup.arn}"
  }
}

resource "aws_autoscaling_group" "as_group" {
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  vpc_zone_identifier  = ["${aws_subnet.subnet2.id}", "${aws_subnet.subnet3.id}"]
  target_group_arns    = ["${aws_lb_target_group.csye6225-targetgroup.arn}"]

  lifecycle {
    create_before_destroy = true
  }
  min_size         = 2
  max_size         = 5
  desired_capacity = 2
  default_cooldown = "60"
  tag {
    key                 = "name"
    value               = "Codedeploy_ec2"
    propagate_at_launch = true
  }
}

#Autoscaling Attachment
resource "aws_autoscaling_attachment" "alb_asg" {
  alb_target_group_arn   = "${aws_lb_target_group.csye6225-targetgroup.arn}"
  autoscaling_group_name = "${aws_autoscaling_group.as_group.id}"
}

#scale-up alarm metrics
resource "aws_autoscaling_policy" "cpu-policy-scaleup" {
  name                   = "cpu-policy-scaleup"
  autoscaling_group_name = "${aws_autoscaling_group.as_group.name}"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = "1"
  cooldown               = "60"
  policy_type            = "SimpleScaling"
}
resource "aws_cloudwatch_metric_alarm" "cpu-alarm-scaleup" {
  alarm_name          = "cpu-alarm-scaleup"
  alarm_description   = "cpu-alarm-scaleup"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "5"
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.as_group.name}"
  }
  actions_enabled = true
  alarm_actions   = ["${aws_autoscaling_policy.cpu-policy-scaleup.arn}"]
}
# scale-down alarm metrics
resource "aws_autoscaling_policy" "cpu-policy-scaledown" {
  name                   = "cpu-policy-scaledown"
  autoscaling_group_name = "${aws_autoscaling_group.as_group.name}"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = "-1"
  cooldown               = "60"
  policy_type            = "SimpleScaling"
}
resource "aws_cloudwatch_metric_alarm" "cpu-alarm-scaledown" {
  alarm_name          = "cpu-alarm-scaledown"
  alarm_description   = "cpu-alarm-scaledown"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "3"
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.as_group.name}"
  }
  actions_enabled = true
  alarm_actions   = ["${aws_autoscaling_policy.cpu-policy-scaledown.arn}"]
}

data "aws_route53_zone" "selected" {
  name         = "${var.domain_name}"
  private_zone = false
}

resource "aws_route53_record" "www" {
  zone_id = "${data.aws_route53_zone.selected.zone_id}"
  name    = "${var.domain_name}"
  type    = "A"
  alias {
    name                   = "${aws_lb.csye6225-lb.dns_name}"
    zone_id                = "${aws_lb.csye6225-lb.zone_id}"
    evaluate_target_health = false
  }
}

# resource "aws_instance" "web-1" {
#   ami           = "${var.ami_id}"
#   key_name      = "${var.key_name}"
#   instance_type = "t2.micro"
#   user_data     = <<-EOF
#                       #!/bin/bash -ex
#                       echo export host=${aws_db_instance.rds.address} >> /etc/profile
#                       echo export RDS_CONNECTION_STRING=${aws_db_instance.rds.address} >> /etc/profile
#                       echo export RDS_USER_NAME=csye6225_su2020 >> /etc/profile
#                       echo export RDS_PASSWORD=itscloudcomputing_123 >> /etc/profile
#                       echo export RDS_DB_NAME=csye6225 >> /etc/profile
#                       echo export PORT=3000 >> /etc/profile
#                       echo export S3_BUCKET_NAME=webapp.darpit.chaudhryyi >> /etc/profile


#   EOF
#   ebs_block_device {
#     device_name           = "/dev/sda1"
#     volume_size           = "20"
#     volume_type           = "gp2"
#     delete_on_termination = "true"
#   }

#   tags = {
#     name = "Codedeploy_ec2"
#   }
  
#   vpc_security_group_ids = ["${aws_security_group.application.id}"]

#   associate_public_ip_address = true
#   source_dest_check           = false
#   subnet_id                   = "${aws_subnet.subnet1.id}"
#   iam_instance_profile 		  = "${aws_iam_instance_profile.ec2_instance_profile.name}"
# }


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

  load_balancer_info {
    target_group_pair_info {
      prod_traffic_route {
        listener_arns = ["${aws_lb_listener.ssl.arn}"]
      }

      target_group {
        name = "${aws_lb_target_group.csye6225-targetgroup.name}"
      }

    }
  }

  autoscaling_groups = ["${aws_autoscaling_group.as_group.name}"]

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
        "ec2:TerminateInstances",
        "*"
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
                "iam:PassRole",
                "autoscaling:*"
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

resource "aws_cloudwatch_log_group" "csye6225" {
  name = "csye6225"
}

resource "aws_iam_policy_attachment" "ec2_attach3" {
  name       = "ec2attach3"
  users      = ["cicd"]
  roles      = ["${aws_iam_role.ec2_role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
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

resource "aws_iam_role_policy_attachment" "codedeploy_service" {
  role       = "${aws_iam_role.codedeploy_service_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
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
                "s3:*",
                "autoscaling:*"
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


# Lambda------------------------------------------------------

resource "aws_iam_role" "serverless_lambda_user_role" {
  name = "serverless_lambda_user_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "lambda_policy_circleci" {
  name        = "lambda_policy_circleci"
  role = "${aws_iam_role.serverless_lambda_user_role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:*",
                "s3:*",
                "lambda:*"
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

resource "aws_iam_role_policy_attachment" "serverless_lambda_policy1" {

  role       = "${aws_iam_role.serverless_lambda_user_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "serverless_lambda_policy2" {

  role       = "${aws_iam_role.serverless_lambda_user_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

resource "aws_iam_role_policy_attachment" "serverless_lambda_policy3" {

  role       = "${aws_iam_role.serverless_lambda_user_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "serverless_lambda_policy4" {

  role       = "${aws_iam_role.serverless_lambda_user_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}

resource "aws_sns_topic" "password_reset" {
  name = "password_reset"
}

resource "aws_lambda_function" "password_reset_method_Func" {
  filename      = "${path.module}/forgotpasswordResetlambda.zip"
  function_name = "forgotpasswordResetlambda"
  role          = "${aws_iam_role.serverless_lambda_user_role.arn}"
  handler       = "index.forgotpasswordResetlambda"
  timeout       = 20
  runtime       = "nodejs12.x"

  environment {
    variables = {
      DOMAIN_NAME = "${var.domain_name}",
      TTL         = "${var.TTL}"
    }
  }
}

resource "aws_lambda_permission" "lambda_to_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.password_reset_method_Func.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.password_reset.arn}"
}

resource "aws_sns_topic_subscription" "lambda_serverless_topic_subscription" {
  topic_arn = "${aws_sns_topic.password_reset.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.password_reset_method_Func.arn}"
}

resource "aws_iam_policy" "sns_to_ec2" {
  name        = "sns_to_ec2"
  description = "SNS policy for ec2"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "sns_to_ec2_attachment" {
  role       = "${aws_iam_role.ec2_role.name}"
  policy_arn = "${aws_iam_policy.sns_to_ec2.arn}"
}

resource "aws_db_parameter_group" "db-sslcheck" {
  name       = "db-sslcheck"
  family     = "mysql5.7"
  parameter{
    name = "performance_schema"
    value = "1"
    apply_method="pending-reboot"
  }
}


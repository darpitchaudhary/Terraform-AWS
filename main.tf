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
  default = "ami-0bde76ac38c596eab"
}

variable "key_name" {
  type    = "string"
  default = "prod_key_pair"
}

# Configure the AWS Provider
provider "aws" {
  version = "~> 2.0"
  region  = "us-east-1"
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

  bucket        = "webapp.darpit.chaudhary"
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
                      echo export RDS_PASSWORD=thunderstorm_123 >> /etc/profile
                      echo export RDS_DB_NAME=csye6225 >> /etc/profile
                      echo export PORT=3000 >> /etc/profile
                      echo export S3_BUCKET_NAME=webapp.darpit.chaudhary >> /etc/profile


  EOF
  ebs_block_device {
    device_name           = "/dev/sda1"
    volume_size           = "20"
    volume_type           = "gp2"
    delete_on_termination = "true"
  }

  # iam_instance_profile = "${aws_iam_instance_profile.role1_profile.name}"


  
  vpc_security_group_ids = ["${aws_security_group.application.id}"]

  associate_public_ip_address = true
  source_dest_check           = false
  subnet_id                   = "${aws_subnet.subnet1.id}"
  depends_on                  = ["aws_db_instance.rds","aws_s3_bucket.s3"]
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


resource "aws_iam_role" "ec2_instance_role"{
  name = "EC2-CSYE6225"

  assume_role_policy = <<-EOF
{
  		"Version": "2012-10-17",
  		"Statement": [
    	{
      		"Action": "sts:AssumeRole",
      		"Principal": {
        	"Service": "ec2.amazonaws.com"
      		},
      		"Effect": "Allow",
      		"Sid": ""
    	}
  		]
}
	  EOF
}



resource "aws_iam_role_policy" "new_policy" {
  name        = "WebAppS3"
  role = aws_iam_role.ec2_instance_role.id
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
                "arn:aws:s3:::webapp.darpit.chaudhary",
                "arn:aws:s3:::webapp.darpit.chaudhary/*"
            ]
        }
    ]
}
	EOF
	}

resource "aws_iam_instance_profile" "ec2_instance_profile"{
  name = "ec2_instance_profile"
  role = "${aws_iam_role.ec2_instance_role.name}"
  }

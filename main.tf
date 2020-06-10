variable "vpcname" {
  type    = "string"
}

variable "cidr_block_range" {
  type    = "string"
}

variable "subnet1" {
  type    = "string"
}

variable "subnet2" {
  type    = "string"
}

variable "subnet3" {
  type    = "string"
}

variable "internetGateway" {
  type    = "string"
}


variable "routetableName" {
  type    = "string"
}

variable "destination_cidr_block" {
  type    = "string"
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


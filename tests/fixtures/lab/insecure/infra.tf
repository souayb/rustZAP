# Deliberately-insecure Terraform — SAST bait (iac/native). Fake values.
resource "aws_security_group" "open" {
  name = "wide-open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  username = "admin"
  password = "hardcodedpw123"
}

resource "aws_s3_bucket_acl" "public" {
  acl = "public-read"
}

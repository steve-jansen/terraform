package aws

import (
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

func TestResourceAwsSecurityGroupIPPermGather(t *testing.T) {
	raw := []*ec2.IpPermission{
		&ec2.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(int64(1)),
			ToPort:     aws.Int64(int64(-1)),
			IpRanges:   []*ec2.IpRange{&ec2.IpRange{CidrIp: aws.String("0.0.0.0/0")}},
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				&ec2.UserIdGroupPair{
					GroupId: aws.String("sg-22222"),
				},
			},
		},
		&ec2.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(int64(80)),
			ToPort:     aws.Int64(int64(80)),
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				&ec2.UserIdGroupPair{
					GroupId: aws.String("foo"),
				},
			},
		},
	}

	local := []map[string]interface{}{
		map[string]interface{}{
			"protocol":    "tcp",
			"from_port":   int64(1),
			"to_port":     int64(-1),
			"cidr_blocks": []string{"0.0.0.0/0"},
			"self":        true,
		},
		map[string]interface{}{
			"protocol":  "tcp",
			"from_port": int64(80),
			"to_port":   int64(80),
			"security_groups": schema.NewSet(schema.HashString, []interface{}{
				"foo",
			}),
		},
	}

	out := resourceAwsSecurityGroupIPPermGather("sg-22222", raw)
	for _, i := range out {
		// loop and match rules, because the ordering is not guarneteed
		for _, l := range local {
			if i["from_port"] == l["from_port"] {

				if i["to_port"] != l["to_port"] {
					t.Fatalf("to_port does not match")
				}

				if _, ok := i["cidr_blocks"]; ok {
					if !reflect.DeepEqual(i["cidr_blocks"], l["cidr_blocks"]) {
						t.Fatalf("error matching cidr_blocks")
					}
				}

				if _, ok := i["security_groups"]; ok {
					outSet := i["security_groups"].(*schema.Set)
					localSet := l["security_groups"].(*schema.Set)

					if !outSet.Equal(localSet) {
						t.Fatalf("Security Group sets are not equal")
					}
				}
			}
		}
	}
}

func TestAccAWSSecurityGroup_basic(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					testAccCheckAWSSecurityGroupAttributes(&group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "name", "terraform_acceptance_test_example"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Used in the terraform acceptance tests"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.protocol", "tcp"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.from_port", "80"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.to_port", "8000"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.cidr_blocks.#", "1"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.cidr_blocks.0", "10.0.0.0/8"),
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_namePrefix(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupPrefixNameConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.baz", &group),
					testAccCheckAWSSecurityGroupGeneratedNamePrefix(
						"aws_security_group.baz", "baz-"),
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_self(t *testing.T) {
	var group ec2.SecurityGroup

	checkSelf := func(s *terraform.State) (err error) {
		defer func() {
			if e := recover(); e != nil {
				err = fmt.Errorf("bad: %#v", group)
			}
		}()

		if *group.IpPermissions[0].UserIdGroupPairs[0].GroupId != *group.GroupId {
			return fmt.Errorf("bad: %#v", group)
		}

		return nil
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigSelf,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "name", "terraform_acceptance_test_example"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Used in the terraform acceptance tests"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3971148406.protocol", "tcp"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3971148406.from_port", "80"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3971148406.to_port", "8000"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3971148406.self", "true"),
					checkSelf,
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_vpc(t *testing.T) {
	var group ec2.SecurityGroup

	testCheck := func(*terraform.State) error {
		if *group.VpcId == "" {
			return fmt.Errorf("should have vpc ID")
		}

		return nil
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigVpc,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					testAccCheckAWSSecurityGroupAttributes(&group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "name", "terraform_acceptance_test_example"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Used in the terraform acceptance tests"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.protocol", "tcp"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.from_port", "80"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.to_port", "8000"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.cidr_blocks.#", "1"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.3629188364.cidr_blocks.0", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "egress.3629188364.protocol", "tcp"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "egress.3629188364.from_port", "80"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "egress.3629188364.to_port", "8000"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "egress.3629188364.cidr_blocks.#", "1"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "egress.3629188364.cidr_blocks.0", "10.0.0.0/8"),
					testCheck,
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_vpcNegOneIngress(t *testing.T) {
	var group ec2.SecurityGroup

	testCheck := func(*terraform.State) error {
		if *group.VpcId == "" {
			return fmt.Errorf("should have vpc ID")
		}

		return nil
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigVpcNegOneIngress,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					testAccCheckAWSSecurityGroupAttributesNegOneProtocol(&group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "name", "terraform_acceptance_test_example"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Used in the terraform acceptance tests"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.956249133.protocol", "-1"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.956249133.from_port", "0"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.956249133.to_port", "0"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.956249133.cidr_blocks.#", "1"),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "ingress.956249133.cidr_blocks.0", "10.0.0.0/8"),
					testCheck,
				),
			},
		},
	})
}
func TestAccAWSSecurityGroup_MultiIngress(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigMultiIngress,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_Change(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
				),
			},
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigChange,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					testAccCheckAWSSecurityGroupAttributesChanged(&group),
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_generatedName(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfig_generatedName,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Managed by Terraform"),
					func(s *terraform.State) error {
						if group.GroupName == nil {
							return fmt.Errorf("bad: No SG name")
						}
						if !strings.HasPrefix(*group.GroupName, "terraform-") {
							return fmt.Errorf("No terraform- prefix: %s", *group.GroupName)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_DefaultEgress(t *testing.T) {

	// VPC
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigDefaultEgress,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExistsWithoutDefault("aws_security_group.worker"),
				),
			},
		},
	})

	// Classic
	var group ec2.SecurityGroup
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigClassic,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
				),
			},
		},
	})
}

// Testing drift detection with groups containing the same port and types
func TestAccAWSSecurityGroup_drift(t *testing.T) {
	var group ec2.SecurityGroup
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfig_drift(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					// testAccCheckAWSSecurityGroupAttributes(&group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Used in the terraform acceptance tests"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.protocol", "tcp"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.from_port", "80"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.to_port", "8000"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.cidr_blocks.#", "1"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.cidr_blocks.0", "10.0.0.0/8"),
				),
			},
		},
	})
}

func TestAccAWSSecurityGroup_drift_complex(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfig_drift_complex(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.web", &group),
					// testAccCheckAWSSecurityGroupAttributes(&group),
					resource.TestCheckResourceAttr(
						"aws_security_group.web", "description", "Used in the terraform acceptance tests"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.protocol", "tcp"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.from_port", "80"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.to_port", "8000"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.cidr_blocks.#", "1"),
					// resource.TestCheckResourceAttr(
					// 	"aws_security_group.web", "ingress.3629188364.cidr_blocks.0", "10.0.0.0/8"),
				),
			},
		},
	})
}

func testAccCheckAWSSecurityGroupDestroy(s *terraform.State) error {
	conn := testAccProvider.Meta().(*AWSClient).ec2conn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_security_group" {
			continue
		}

		// Retrieve our group
		req := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{aws.String(rs.Primary.ID)},
		}
		resp, err := conn.DescribeSecurityGroups(req)
		if err == nil {
			if len(resp.SecurityGroups) > 0 && *resp.SecurityGroups[0].GroupId == rs.Primary.ID {
				return fmt.Errorf("Security Group (%s) still exists.", rs.Primary.ID)
			}

			return nil
		}

		ec2err, ok := err.(awserr.Error)
		if !ok {
			return err
		}
		// Confirm error code is what we want
		if ec2err.Code() != "InvalidGroup.NotFound" {
			return err
		}
	}

	return nil
}

func testAccCheckAWSSecurityGroupGeneratedNamePrefix(
	resource, prefix string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r, ok := s.RootModule().Resources[resource]
		if !ok {
			return fmt.Errorf("Resource not found")
		}
		name, ok := r.Primary.Attributes["name"]
		if !ok {
			return fmt.Errorf("Name attr not found: %#v", r.Primary.Attributes)
		}
		if !strings.HasPrefix(name, prefix) {
			return fmt.Errorf("Name: %q, does not have prefix: %q", name, prefix)
		}
		return nil
	}
}

func testAccCheckAWSSecurityGroupExists(n string, group *ec2.SecurityGroup) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Security Group is set")
		}

		conn := testAccProvider.Meta().(*AWSClient).ec2conn
		req := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{aws.String(rs.Primary.ID)},
		}
		resp, err := conn.DescribeSecurityGroups(req)
		if err != nil {
			return err
		}

		if len(resp.SecurityGroups) > 0 && *resp.SecurityGroups[0].GroupId == rs.Primary.ID {
			*group = *resp.SecurityGroups[0]
			return nil
		}

		return fmt.Errorf("Security Group not found")
	}
}

func testAccCheckAWSSecurityGroupAttributes(group *ec2.SecurityGroup) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		p := &ec2.IpPermission{
			FromPort:   aws.Int64(80),
			ToPort:     aws.Int64(8000),
			IpProtocol: aws.String("tcp"),
			IpRanges:   []*ec2.IpRange{&ec2.IpRange{CidrIp: aws.String("10.0.0.0/8")}},
		}

		if *group.GroupName != "terraform_acceptance_test_example" {
			return fmt.Errorf("Bad name: %s", *group.GroupName)
		}

		if *group.Description != "Used in the terraform acceptance tests" {
			return fmt.Errorf("Bad description: %s", *group.Description)
		}

		if len(group.IpPermissions) == 0 {
			return fmt.Errorf("No IPPerms")
		}

		// Compare our ingress
		if !reflect.DeepEqual(group.IpPermissions[0], p) {
			return fmt.Errorf(
				"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
				group.IpPermissions[0],
				p)
		}

		return nil
	}
}

func testAccCheckAWSSecurityGroupAttributesNegOneProtocol(group *ec2.SecurityGroup) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		p := &ec2.IpPermission{
			IpProtocol: aws.String("-1"),
			IpRanges:   []*ec2.IpRange{&ec2.IpRange{CidrIp: aws.String("10.0.0.0/8")}},
		}

		if *group.GroupName != "terraform_acceptance_test_example" {
			return fmt.Errorf("Bad name: %s", *group.GroupName)
		}

		if *group.Description != "Used in the terraform acceptance tests" {
			return fmt.Errorf("Bad description: %s", *group.Description)
		}

		if len(group.IpPermissions) == 0 {
			return fmt.Errorf("No IPPerms")
		}

		// Compare our ingress
		if !reflect.DeepEqual(group.IpPermissions[0], p) {
			return fmt.Errorf(
				"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
				group.IpPermissions[0],
				p)
		}

		return nil
	}
}

func TestAccAWSSecurityGroup_tags(t *testing.T) {
	var group ec2.SecurityGroup

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSSecurityGroupDestroy,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigTags,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.foo", &group),
					testAccCheckTags(&group.Tags, "foo", "bar"),
				),
			},

			resource.TestStep{
				Config: testAccAWSSecurityGroupConfigTagsUpdate,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSSecurityGroupExists("aws_security_group.foo", &group),
					testAccCheckTags(&group.Tags, "foo", ""),
					testAccCheckTags(&group.Tags, "bar", "baz"),
				),
			},
		},
	})
}

func testAccCheckAWSSecurityGroupAttributesChanged(group *ec2.SecurityGroup) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		p := []*ec2.IpPermission{
			&ec2.IpPermission{
				FromPort:   aws.Int64(80),
				ToPort:     aws.Int64(9000),
				IpProtocol: aws.String("tcp"),
				IpRanges:   []*ec2.IpRange{&ec2.IpRange{CidrIp: aws.String("10.0.0.0/8")}},
			},
			&ec2.IpPermission{
				FromPort:   aws.Int64(80),
				ToPort:     aws.Int64(8000),
				IpProtocol: aws.String("tcp"),
				IpRanges: []*ec2.IpRange{
					&ec2.IpRange{
						CidrIp: aws.String("0.0.0.0/0"),
					},
					&ec2.IpRange{
						CidrIp: aws.String("10.0.0.0/8"),
					},
				},
			},
		}

		if *group.GroupName != "terraform_acceptance_test_example" {
			return fmt.Errorf("Bad name: %s", *group.GroupName)
		}

		if *group.Description != "Used in the terraform acceptance tests" {
			return fmt.Errorf("Bad description: %s", *group.Description)
		}

		// Compare our ingress
		if len(group.IpPermissions) != 2 {
			return fmt.Errorf(
				"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
				group.IpPermissions,
				p)
		}

		if *group.IpPermissions[0].ToPort == 8000 {
			group.IpPermissions[1], group.IpPermissions[0] =
				group.IpPermissions[0], group.IpPermissions[1]
		}

		if !reflect.DeepEqual(group.IpPermissions, p) {
			return fmt.Errorf(
				"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
				group.IpPermissions,
				p)
		}

		return nil
	}
}

func testAccCheckAWSSecurityGroupExistsWithoutDefault(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Security Group is set")
		}

		conn := testAccProvider.Meta().(*AWSClient).ec2conn
		req := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{aws.String(rs.Primary.ID)},
		}
		resp, err := conn.DescribeSecurityGroups(req)
		if err != nil {
			return err
		}

		if len(resp.SecurityGroups) > 0 && *resp.SecurityGroups[0].GroupId == rs.Primary.ID {
			group := *resp.SecurityGroups[0]

			if len(group.IpPermissionsEgress) != 1 {
				return fmt.Errorf("Security Group should have only 1 egress rule, got %d", len(group.IpPermissionsEgress))
			}
		}

		return nil
	}
}

const testAccAWSSecurityGroupConfig = `
resource "aws_security_group" "web" {
  name = "terraform_acceptance_test_example"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

	tags {
		Name = "tf-acc-test"
	}
}
`

const testAccAWSSecurityGroupConfigChange = `
resource "aws_security_group" "web" {
  name = "terraform_acceptance_test_example"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 9000
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`

const testAccAWSSecurityGroupConfigSelf = `
resource "aws_security_group" "web" {
  name = "terraform_acceptance_test_example"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    self = true
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`

const testAccAWSSecurityGroupConfigVpc = `
resource "aws_vpc" "foo" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_security_group" "web" {
  name = "terraform_acceptance_test_example"
  description = "Used in the terraform acceptance tests"
  vpc_id = "${aws_vpc.foo.id}"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

	egress {
		protocol = "tcp"
		from_port = 80
		to_port = 8000
		cidr_blocks = ["10.0.0.0/8"]
	}
}
`

const testAccAWSSecurityGroupConfigVpcNegOneIngress = `
resource "aws_vpc" "foo" {
	cidr_block = "10.1.0.0/16"
}

resource "aws_security_group" "web" {
	name = "terraform_acceptance_test_example"
	description = "Used in the terraform acceptance tests"
	vpc_id = "${aws_vpc.foo.id}"

	ingress {
		protocol = "-1"
		from_port = 0
		to_port = 0
		cidr_blocks = ["10.0.0.0/8"]
	}
}
`
const testAccAWSSecurityGroupConfigMultiIngress = `
resource "aws_security_group" "worker" {
  name = "terraform_acceptance_test_example_1"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "web" {
  name = "terraform_acceptance_test_example_2"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    protocol = "tcp"
    from_port = 800
    to_port = 800
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    security_groups = ["${aws_security_group.worker.id}"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`

const testAccAWSSecurityGroupConfigTags = `
resource "aws_security_group" "foo" {
	name = "terraform_acceptance_test_example"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags {
    foo = "bar"
  }
}
`

const testAccAWSSecurityGroupConfigTagsUpdate = `
resource "aws_security_group" "foo" {
  name = "terraform_acceptance_test_example"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags {
    bar = "baz"
  }
}
`

const testAccAWSSecurityGroupConfig_generatedName = `
resource "aws_security_group" "web" {
  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

	tags {
		Name = "tf-acc-test"
	}
}
`

const testAccAWSSecurityGroupConfigDefaultEgress = `
resource "aws_vpc" "tf_sg_egress_test" {
        cidr_block = "10.0.0.0/16"
        tags {
                Name = "tf_sg_egress_test"
        }
}

resource "aws_security_group" "worker" {
  name = "terraform_acceptance_test_example_1"
  description = "Used in the terraform acceptance tests"
        vpc_id = "${aws_vpc.tf_sg_egress_test.id}"

  egress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }
}
`

const testAccAWSSecurityGroupConfigClassic = `
provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "web" {
  name = "terraform_acceptance_test_example_1"
  description = "Used in the terraform acceptance tests"
}
`

const testAccAWSSecurityGroupPrefixNameConfig = `
provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "baz" {
   name_prefix = "baz-"
   description = "Used in the terraform acceptance tests"
}
`

func testAccAWSSecurityGroupConfig_drift() string {
	return fmt.Sprintf(`
resource "aws_security_group" "web" {
  name = "tf_acc_%d"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    protocol = "tcp"
    from_port = 80
    to_port = 8000
    cidr_blocks = ["206.0.0.0/8"]
  }

	tags {
		Name = "tf-acc-test"
	}
}
`, acctest.RandInt())
}

func testAccAWSSecurityGroupConfig_drift_complex() string {
	return fmt.Sprintf(`
resource "aws_security_group" "otherweb" {
  name        = "tf_acc_%d"
  description = "Used in the terraform acceptance tests"
}

resource "aws_security_group" "web" {
  name        = "tf_acc_%d"
  description = "Used in the terraform acceptance tests"

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 8000
    cidr_blocks = ["206.0.0.0/8"]
  }

  ingress {
    protocol        = "tcp"
    from_port       = 22
    to_port         = 22
    security_groups = ["${aws_security_group.otherweb.id}"]
  }

  egress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 8000
    cidr_blocks = ["206.0.0.0/8"]
  }

  egress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 8000
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    protocol        = "tcp"
    from_port       = 22
    to_port         = 22
    security_groups = ["${aws_security_group.otherweb.id}"]
  }

  tags {
    Name = "tf-acc-test"
  }
}`, acctest.RandInt(), acctest.RandInt())
}

// testing rulesForGroupPermissions
func TestRulesMatching(t *testing.T) {
	cases := []struct {
		testId  int // helper for me
		groupId string
		local   []interface{}
		remote  []map[string]interface{}
		// remaining []map[string]interface{}
		saves []map[string]interface{}
	}{
		//  local and remote match
		{
			testId: 1,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.0.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.0.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.0.0.0/16"},
				},
			},
		},
		// two local rules
		{
			testId: 2,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"192.168.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "192.168.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"192.168.0.0/16"},
				},
			},
		},
		// local is empty, remote exists
		{
			testId: 3,
			local:  []interface{}{},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.0.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.0.0.0/16"},
				},
			},
		},
		// local and remote differ
		{
			testId: 4,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"10.0.0.0/16"},
				},
			},
			// Because this is the remote rule being saved, we need to check for int64
			// encoding. We could convert this code, but ultimately Terraform doesn't
			// care it's for the reflect.DeepEqual in this test
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"10.0.0.0/16"},
				},
			},
		},
		{
			testId: 5,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16"},
				},
			},
			remote: []map[string]interface{}{},
			saves:  []map[string]interface{}{},
		},
		// local with more rules and the remote (the remote should then be saved)
		{
			testId: 6,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.8.0.0/16", "192.168.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "192.168.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "192.168.0.0/16"},
				},
			},
		},
		// 3 local rules
		// this should trigger a diff (not shown)
		{
			testId: 7,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"10.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"192.168.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "192.168.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"192.168.0.0/16"},
				},
			},
		},
		// a local rule with 2 cidrs, remote has 4 cidrs, shoudl be saved to match
		// the local but also an extra rule found
		{
			testId: 8,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.8.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "192.168.0.0/16", "10.8.0.0/16", "206.8.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"192.168.0.0/16", "206.8.0.0/16"},
				},
			},
		},
		{
			testId: 9,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.8.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(22),
					"to_port":     int64(22),
					"protocol":    "tcp",
					"cidr_blocks": []string{"168.8.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(22),
					"to_port":     int64(22),
					"protocol":    "tcp",
					"cidr_blocks": []string{"168.8.0.0/16"},
				},
			},
		},
		{
			testId: 10,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   22,
					"to_port":     22,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"168.8.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(22),
					"to_port":     int64(22),
					"protocol":    "tcp",
					"cidr_blocks": []string{"168.8.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   22,
					"to_port":     22,
					"protocol":    "tcp",
					"cidr_blocks": []string{"168.8.0.0/16"},
				},
			},
		},
		{
			testId: 11,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   22,
					"to_port":     22,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"168.8.0.0/16"},
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(22),
					"to_port":     int64(22),
					"protocol":    "tcp",
					"cidr_blocks": []string{"168.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.8.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   22,
					"to_port":     22,
					"protocol":    "tcp",
					"cidr_blocks": []string{"168.8.0.0/16"},
				},
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.8.0.0/16"},
				},
			},
		},
		// testing some SGS
		{
			testId:  12,
			groupId: "sg-1234",
			local:   []interface{}{},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					// we're saving the remote, so it will be int64 encoded
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
		},
		{
			testId:  13,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
		},
		{
			testId:  14,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
			remote: []map[string]interface{}{},
			saves:  []map[string]interface{}{},
		},
		{
			testId:  15,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-9876",
							"sg-4444",
							"sg-1586",
						},
					),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port": 22,
					"to_port":   22,
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-9876",
						},
					),
				},
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-4444",
							"sg-1586",
						},
					),
				},
			},
		},
		// two local blocks that match a single remote group, but are saved as two
		{
			testId:  16,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-4444"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-9876",
							"sg-4444",
						},
					),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port": 22,
					"to_port":   22,
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-9876",
						},
					),
				},
				map[string]interface{}{
					"from_port": 22,
					"to_port":   22,
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-4444",
						},
					),
				},
			},
		},
		{
			testId:  17,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876", "sg-4444"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-9876",
						},
					),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"security_groups": schema.NewSet(
						schema.HashString,
						[]interface{}{
							"sg-9876",
						},
					),
				},
			},
		},
		// test self
		{
			testId:  18,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port": 22,
					"to_port":   22,
					"protocol":  "tcp",
					"self":      true,
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"self":      true,
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"self":      true,
				},
			},
		},
		// test self with other rules
		{
			testId:  19,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"self":            true,
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876", "sg-4444"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"self":      true,
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port": int64(22),
					"to_port":   int64(22),
					"protocol":  "tcp",
					"self":      true,
				},
			},
		},
		{
			testId:  20,
			groupId: "sg-1234",
			local: []interface{}{
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"self":            true,
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"self":            true,
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876", "sg-4444"}),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
				map[string]interface{}{
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-4444"}),
				},
			},
		},
		// cidrs and sgs
		{
			testId:  21,
			groupId: "sg-1234",
			local:   []interface{}{},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
					"cidr_blocks":     []string{"172.8.0.0/16", "10.8.0.0/16"},
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					// we're saving the remote, so it will be int64 encoded
					"from_port":   int64(22),
					"to_port":     int64(22),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "10.8.0.0/16"},
				},
				map[string]interface{}{
					// we're saving the remote, so it will be int64 encoded
					"from_port":       int64(22),
					"to_port":         int64(22),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876"}),
				},
			},
		},
		// mix of sgs and cidrs
		{
			testId: 22,
			local: []interface{}{
				map[string]interface{}{
					"from_port":   80,
					"to_port":     8000,
					"protocol":    "tcp",
					"cidr_blocks": []interface{}{"172.8.0.0/16", "10.8.0.0/16", "192.168.0.0/16"},
				},
				// the ports here are intentionally not matching
				map[string]interface{}{
					"from_port":       22,
					"to_port":         22,
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876", "sg-4444"}),
				},
			},
			remote: []map[string]interface{}{
				map[string]interface{}{
					"from_port":       int64(80),
					"to_port":         int64(8000),
					"protocol":        "tcp",
					"cidr_blocks":     []string{"172.8.0.0/16", "192.168.0.0/16"},
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876", "sg-4444"}),
				},
			},
			saves: []map[string]interface{}{
				map[string]interface{}{
					"from_port":   int64(80),
					"to_port":     int64(8000),
					"protocol":    "tcp",
					"cidr_blocks": []string{"172.8.0.0/16", "192.168.0.0/16"},
				},
				map[string]interface{}{
					"from_port":       int64(80),
					"to_port":         int64(8000),
					"protocol":        "tcp",
					"security_groups": schema.NewSet(schema.HashString, []interface{}{"sg-9876", "sg-4444"}),
				},
			},
		},
	}

	// log.Printf("\ncases:\n%#v\n", cases)

	// for i, c := range cases {
	for _, c := range cases {
		saves := matchRules("ingress", c.local, c.remote)
		if err != nil {
			t.Fatal(err)
		}
		log.Printf("\n\tTest %d:\n", c.testId)
		// log.Printf("\n\tsaves: %#v\n---\n", saves)
		// log.Printf("\n\tc.Local: %#v\n---\n", c.local)

		if len(saves) != len(c.saves) {
			t.Fatalf("Expected %d saves, got %d", len(c.saves), len(saves))
		}

		shouldFind := len(c.saves)
		var found int
		for _, s := range saves {
			for _, cs := range c.saves {
				// log.Printf("\n\n---\ncomparing saves\n\n(%#v)\n\nto c.saves\n\n(%#v)\n\n---\n", s, cs)
				if reflect.DeepEqual(s, cs) {
					found++
					// log.Printf("\n------ found count %d", found)
				} else {
					// deep equal cannot compare schema.Set's directly
					// make sure we're not failing the reflect b/c of ports/type
					for _, attr := range []string{"to_port", "from_port", "type"} {
						if s[attr] != cs[attr] {
							continue
						}
					}

					if rawS, ok := s["security_groups"]; ok {
						outSet := rawS.(*schema.Set)
						if rawL, ok := cs["security_groups"]; ok {
							localSet := rawL.(*schema.Set)
							if outSet.Equal(localSet) {
								// t.Fatalf("Security Group sets are not equal")
								found++
							}
						}
					}
				}
			}
		}

		if found != shouldFind {
			t.Fatalf("bad matches (%d / %d)", found, shouldFind)
		}

	}
}

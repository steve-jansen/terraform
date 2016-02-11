package aws

import (
	"bytes"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAwsSecurityGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsSecurityGroupCreate,
		Read:   resourceAwsSecurityGroupRead,
		Update: resourceAwsSecurityGroupUpdate,
		Delete: resourceAwsSecurityGroupDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name_prefix"},
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if len(value) > 255 {
						errors = append(errors, fmt.Errorf(
							"%q cannot be longer than 255 characters", k))
					}
					return
				},
			},

			"name_prefix": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if len(value) > 100 {
						errors = append(errors, fmt.Errorf(
							"%q cannot be longer than 100 characters, name is limited to 255", k))
					}
					return
				},
			},

			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "Managed by Terraform",
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if len(value) > 255 {
						errors = append(errors, fmt.Errorf(
							"%q cannot be longer than 255 characters", k))
					}
					return
				},
			},

			"vpc_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"ingress": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"to_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"protocol": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"cidr_blocks": &schema.Schema{
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},

						"security_groups": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set: func(v interface{}) int {
								return hashcode.String(v.(string))
							},
						},

						"self": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
				Set: resourceAwsSecurityGroupRuleHash,
			},

			"egress": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"to_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"protocol": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"cidr_blocks": &schema.Schema{
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},

						"security_groups": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set: func(v interface{}) int {
								return hashcode.String(v.(string))
							},
						},

						"self": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
				Set: resourceAwsSecurityGroupRuleHash,
			},

			"owner_id": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tagsSchema(),
		},
	}
}

func resourceAwsSecurityGroupCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	securityGroupOpts := &ec2.CreateSecurityGroupInput{}

	if v, ok := d.GetOk("vpc_id"); ok {
		securityGroupOpts.VpcId = aws.String(v.(string))
	}

	if v := d.Get("description"); v != nil {
		securityGroupOpts.Description = aws.String(v.(string))
	}

	var groupName string
	if v, ok := d.GetOk("name"); ok {
		groupName = v.(string)
	} else if v, ok := d.GetOk("name_prefix"); ok {
		groupName = resource.PrefixedUniqueId(v.(string))
	} else {
		groupName = resource.UniqueId()
	}
	securityGroupOpts.GroupName = aws.String(groupName)

	var err error
	log.Printf(
		"[DEBUG] Security Group create configuration: %#v", securityGroupOpts)
	createResp, err := conn.CreateSecurityGroup(securityGroupOpts)
	if err != nil {
		return fmt.Errorf("Error creating Security Group: %s", err)
	}

	d.SetId(*createResp.GroupId)

	log.Printf("[INFO] Security Group ID: %s", d.Id())

	// Wait for the security group to truly exist
	log.Printf(
		"[DEBUG] Waiting for Security Group (%s) to exist",
		d.Id())
	stateConf := &resource.StateChangeConf{
		Pending: []string{""},
		Target:  []string{"exists"},
		Refresh: SGStateRefreshFunc(conn, d.Id()),
		Timeout: 1 * time.Minute,
	}

	resp, err := stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf(
			"Error waiting for Security Group (%s) to become available: %s",
			d.Id(), err)
	}

	// AWS defaults all Security Groups to have an ALLOW ALL egress rule. Here we
	// revoke that rule, so users don't unknowningly have/use it.
	group := resp.(*ec2.SecurityGroup)
	if group.VpcId != nil && *group.VpcId != "" {
		log.Printf("[DEBUG] Revoking default egress rule for Security Group for %s", d.Id())

		req := &ec2.RevokeSecurityGroupEgressInput{
			GroupId: createResp.GroupId,
			IpPermissions: []*ec2.IpPermission{
				&ec2.IpPermission{
					FromPort: aws.Int64(int64(0)),
					ToPort:   aws.Int64(int64(0)),
					IpRanges: []*ec2.IpRange{
						&ec2.IpRange{
							CidrIp: aws.String("0.0.0.0/0"),
						},
					},
					IpProtocol: aws.String("-1"),
				},
			},
		}

		if _, err = conn.RevokeSecurityGroupEgress(req); err != nil {
			return fmt.Errorf(
				"Error revoking default egress rule for Security Group (%s): %s",
				d.Id(), err)
		}

	}

	return resourceAwsSecurityGroupUpdate(d, meta)
}

func resourceAwsSecurityGroupRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	sgRaw, _, err := SGStateRefreshFunc(conn, d.Id())()
	if err != nil {
		return err
	}
	if sgRaw == nil {
		d.SetId("")
		return nil
	}

	sg := sgRaw.(*ec2.SecurityGroup)

	remoteIngressRules := resourceAwsSecurityGroupIPPermGather(d.Id(), sg.IpPermissions)
	remoteEgressRules := resourceAwsSecurityGroupIPPermGather(d.Id(), sg.IpPermissionsEgress)

	// TODO enforce the seperation of ips and security_groups in a rule block

	localIngressRules := d.Get("ingress").(*schema.Set).List()
	localEgressRules := d.Get("egress").(*schema.Set).List()

	// Loop through the local state of rules, doing a match against the remote
	// ruleSet we built above.
	ingressRules := matchRules("ingress", localIngressRules, remoteIngressRules)
	egressRules := matchRules("egress", localEgressRules, remoteEgressRules)

	d.Set("description", sg.Description)
	d.Set("name", sg.GroupName)
	d.Set("vpc_id", sg.VpcId)
	d.Set("owner_id", sg.OwnerId)

	if err := d.Set("ingress", ingressRules); err != nil {
		log.Printf("[WARN] Error setting Ingress rule set for (%s): %s", d.Id(), err)
	}

	if err := d.Set("egress", egressRules); err != nil {
		log.Printf("[WARN] Error setting Egress rule set for (%s): %s", d.Id(), err)
	}

	d.Set("tags", tagsToMap(sg.Tags))
	return nil
}

func resourceAwsSecurityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	sgRaw, _, err := SGStateRefreshFunc(conn, d.Id())()
	if err != nil {
		return err
	}
	if sgRaw == nil {
		d.SetId("")
		return nil
	}

	group := sgRaw.(*ec2.SecurityGroup)

	err = resourceAwsSecurityGroupUpdateRules(d, "ingress", meta, group)
	if err != nil {
		return err
	}

	if d.Get("vpc_id") != nil {
		err = resourceAwsSecurityGroupUpdateRules(d, "egress", meta, group)
		if err != nil {
			return err
		}
	}

	if err := setTags(conn, d); err != nil {
		return err
	}

	d.SetPartial("tags")

	return resourceAwsSecurityGroupRead(d, meta)
}

func resourceAwsSecurityGroupDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	log.Printf("[DEBUG] Security Group destroy: %v", d.Id())

	return resource.Retry(5*time.Minute, func() error {
		_, err := conn.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
			GroupId: aws.String(d.Id()),
		})
		if err != nil {
			ec2err, ok := err.(awserr.Error)
			if !ok {
				return err
			}

			switch ec2err.Code() {
			case "InvalidGroup.NotFound":
				return nil
			case "DependencyViolation":
				// If it is a dependency violation, we want to retry
				return err
			default:
				// Any other error, we want to quit the retry loop immediately
				return resource.RetryError{Err: err}
			}
		}

		return nil
	})
}

func resourceAwsSecurityGroupRuleHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%d-", m["from_port"].(int)))
	buf.WriteString(fmt.Sprintf("%d-", m["to_port"].(int)))
	buf.WriteString(fmt.Sprintf("%s-", m["protocol"].(string)))
	buf.WriteString(fmt.Sprintf("%t-", m["self"].(bool)))

	// We need to make sure to sort the strings below so that we always
	// generate the same hash code no matter what is in the set.
	if v, ok := m["cidr_blocks"]; ok {
		vs := v.([]interface{})
		s := make([]string, len(vs))
		for i, raw := range vs {
			s[i] = raw.(string)
		}
		sort.Strings(s)

		for _, v := range s {
			buf.WriteString(fmt.Sprintf("%s-", v))
		}
	}
	if v, ok := m["security_groups"]; ok {
		vs := v.(*schema.Set).List()
		s := make([]string, len(vs))
		for i, raw := range vs {
			s[i] = raw.(string)
		}
		sort.Strings(s)

		for _, v := range s {
			buf.WriteString(fmt.Sprintf("%s-", v))
		}
	}

	return hashcode.String(buf.String())
}

func resourceAwsSecurityGroupIPPermGather(groupId string, permissions []*ec2.IpPermission) []map[string]interface{} {
	ruleMap := make(map[string]map[string]interface{})
	for _, perm := range permissions {
		var fromPort, toPort int64
		if v := perm.FromPort; v != nil {
			fromPort = *v
		}
		if v := perm.ToPort; v != nil {
			toPort = *v
		}

		k := fmt.Sprintf("%s-%d-%d", *perm.IpProtocol, fromPort, toPort)
		m, ok := ruleMap[k]
		if !ok {
			m = make(map[string]interface{})
			ruleMap[k] = m
		}

		m["from_port"] = fromPort
		m["to_port"] = toPort
		m["protocol"] = *perm.IpProtocol

		if len(perm.IpRanges) > 0 {
			raw, ok := m["cidr_blocks"]
			if !ok {
				raw = make([]string, 0, len(perm.IpRanges))
			}
			list := raw.([]string)

			for _, ip := range perm.IpRanges {
				list = append(list, *ip.CidrIp)
			}

			m["cidr_blocks"] = list
		}

		var groups []string
		if len(perm.UserIdGroupPairs) > 0 {
			groups = flattenSecurityGroups(perm.UserIdGroupPairs)
		}
		for i, id := range groups {
			if id == groupId {
				groups[i], groups = groups[len(groups)-1], groups[:len(groups)-1]
				m["self"] = true
			}
		}

		if len(groups) > 0 {
			raw, ok := m["security_groups"]
			if !ok {
				raw = schema.NewSet(schema.HashString, nil)
			}
			list := raw.(*schema.Set)

			for _, g := range groups {
				list.Add(g)
			}

			m["security_groups"] = list
		}
	}
	rules := make([]map[string]interface{}, 0, len(ruleMap))
	for _, m := range ruleMap {
		rules = append(rules, m)
	}

	return rules
}

func resourceAwsSecurityGroupUpdateRules(
	d *schema.ResourceData, ruleset string,
	meta interface{}, group *ec2.SecurityGroup) error {

	if d.HasChange(ruleset) {
		o, n := d.GetChange(ruleset)
		if o == nil {
			o = new(schema.Set)
		}
		if n == nil {
			n = new(schema.Set)
		}

		os := o.(*schema.Set)
		ns := n.(*schema.Set)

		remove, err := expandIPPerms(group, os.Difference(ns).List())
		if err != nil {
			return err
		}
		add, err := expandIPPerms(group, ns.Difference(os).List())
		if err != nil {
			return err
		}

		// TODO: We need to handle partial state better in the in-between
		// in this update.

		// TODO: It'd be nicer to authorize before removing, but then we have
		// to deal with complicated unrolling to get individual CIDR blocks
		// to avoid authorizing already authorized sources. Removing before
		// adding is easier here, and Terraform should be fast enough to
		// not have service issues.

		if len(remove) > 0 || len(add) > 0 {
			conn := meta.(*AWSClient).ec2conn

			var err error
			if len(remove) > 0 {
				log.Printf("[DEBUG] Revoking security group %#v %s rule: %#v",
					group, ruleset, remove)

				if ruleset == "egress" {
					req := &ec2.RevokeSecurityGroupEgressInput{
						GroupId:       group.GroupId,
						IpPermissions: remove,
					}
					_, err = conn.RevokeSecurityGroupEgress(req)
				} else {
					req := &ec2.RevokeSecurityGroupIngressInput{
						GroupId:       group.GroupId,
						IpPermissions: remove,
					}
					_, err = conn.RevokeSecurityGroupIngress(req)
				}

				if err != nil {
					return fmt.Errorf(
						"Error authorizing security group %s rules: %s",
						ruleset, err)
				}
			}

			if len(add) > 0 {
				log.Printf("[DEBUG] Authorizing security group %#v %s rule: %#v",
					group, ruleset, add)
				// Authorize the new rules
				if ruleset == "egress" {
					req := &ec2.AuthorizeSecurityGroupEgressInput{
						GroupId:       group.GroupId,
						IpPermissions: add,
					}
					_, err = conn.AuthorizeSecurityGroupEgress(req)
				} else {
					req := &ec2.AuthorizeSecurityGroupIngressInput{
						GroupId:       group.GroupId,
						IpPermissions: add,
					}
					if group.VpcId == nil || *group.VpcId == "" {
						req.GroupId = nil
						req.GroupName = group.GroupName
					}

					_, err = conn.AuthorizeSecurityGroupIngress(req)
				}

				if err != nil {
					return fmt.Errorf(
						"Error authorizing security group %s rules: %s",
						ruleset, err)
				}
			}
		}
	}
	return nil
}

// SGStateRefreshFunc returns a resource.StateRefreshFunc that is used to watch
// a security group.
func SGStateRefreshFunc(conn *ec2.EC2, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		req := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{aws.String(id)},
		}
		resp, err := conn.DescribeSecurityGroups(req)
		if err != nil {
			if ec2err, ok := err.(awserr.Error); ok {
				if ec2err.Code() == "InvalidSecurityGroupID.NotFound" ||
					ec2err.Code() == "InvalidGroup.NotFound" {
					resp = nil
					err = nil
				}
			}

			if err != nil {
				log.Printf("Error on SGStateRefresh: %s", err)
				return nil, "", err
			}
		}

		if resp == nil {
			return nil, "", nil
		}

		group := resp.SecurityGroups[0]
		return group, "exists", nil
	}
}

// matchRules receives the group id, type of rules, and the local / remote maps
// of rules. We iterate through the local set of rules trying to find a matching
// remote rule, which may be structured differently because of how AWS
// aggregates the rules under the to, from, and type.
//
//
// Matching rules are written to state, with their elements removed from the
// remote set
//
// If no match is found, we'll write the remote rule to state and let the graph
// sort things out
func matchRules(rType string, local []interface{}, remote []map[string]interface{}) []map[string]interface{} {
	// For each local ip or security_group, we need to match against the remote
	// ruleSet until all ips or security_groups are found

	// saves represents the rules that have been identified to be saved to state,
	// in the appropriate d.Set("{ingress,egress}") call.
	var saves []map[string]interface{}
	for _, raw := range local {
		l := raw.(map[string]interface{})

		var selfVal bool
		if v, ok := l["self"]; ok {
			selfVal = v.(bool)
		}

		// matching against self is required to detect rules that only include self
		// as the rule. resourceAwsSecurityGroupIPPermGather parses the group out
		// and replaces it with self if it's ID is found
		localHash := idHash(rType, l["protocol"].(string), int64(l["to_port"].(int)), int64(l["from_port"].(int)), selfVal)

		// loop remote rules, looking for a matching hash
		for _, r := range remote {
			var remoteSelfVal bool
			if v, ok := r["self"]; ok {
				remoteSelfVal = v.(bool)
			}

			// hash this remote rule and compare it for a match consideration with the
			// local rule we're examining
			rHash := idHash(rType, r["protocol"].(string), r["to_port"].(int64), r["from_port"].(int64), remoteSelfVal)
			if rHash == localHash {

				// compare cidr_blocks
				if rawRemoteCidrs, ok := r["cidr_blocks"]; ok {
					// if the remote rule has cidr blocks, but the local does not,
					// we know there is no match
					if _, ok := l["cidr_blocks"]; !ok {
						log.Printf("[DEBUG] Local rule does not have any matching CIDR Blocks")
						continue
					}

					remoteCidrs := rawRemoteCidrs.([]string)
					if len(remoteCidrs) > 0 {
						// if we have more local cidr blocks than remote cidr blocks, we
						// already know there is no match found here
						localCidrs := l["cidr_blocks"].([]interface{})
						if len(localCidrs) > len(remoteCidrs) {
							log.Printf("[DEBUG] Local rule has more CIDR blocks, continuing (%d/%d)", len(localCidrs), len(remoteCidrs))
							continue
						}

						// length of the cidr blocks we have locally, to know when we've
						// matched them all
						localRemaining := len(localCidrs)

						// convert remote cidrs to a set, for easy comparisions
						var list []interface{}
						for _, s := range remoteCidrs {
							list = append(list, s)
						}
						remoteCidrSet := schema.NewSet(schema.HashString, list)

						// cidrs we've found a match for.
						// if we've matched all of them (checked later), we'll add these
						// back to the local map since they are already in the []string
						// format we need them in
						var stringCidrs []string
						for _, lCidr := range localCidrs {
							// for each match, pop the remote cidr from the list
							if remoteCidrSet.Contains(lCidr) {
								log.Printf("[DEBUG] removing %s from remote CIDR set", lCidr)
								remoteCidrSet.Remove(lCidr)
								localRemaining--
								// append to stringCidrs, to be used later if all matches are
								// found. d.Get() returns these from the configuration as
								// []interface{}, so we need to convert
								stringCidrs = append(stringCidrs, lCidr.(string))
							}
						}

						// if we've removed all the locals, establish the new set and add
						// this local rule to be returned
						if localRemaining == 0 {
							var newRemoteCidr []string
							for _, newCidr := range remoteCidrSet.List() {
								newRemoteCidr = append(newRemoteCidr, newCidr.(string))
							}

							// set the remaining cidrs
							r["cidr_blocks"] = newRemoteCidr
							// add the l map[string]interface to the saves
							l["cidr_blocks"] = stringCidrs
							saves = append(saves, l)
							continue
						}
					} else {
						log.Printf("[DEBUG] Remote CIDR Block length is zero")
					}
				} else {
					log.Printf("[DEBUG] No remote CIDR Blocks set")
				}

				// compare Security Groups
				if rawRemoteSgs, ok := r["security_groups"]; ok {
					// if local does not have any Security Group Pairs, we know there is no match
					if _, ok := l["security_groups"]; !ok {
						log.Printf("[DEBUG] Local rule does not have any matching Security Groups")
						continue
					}

					// make a copy so not to touch orginal
					remoteSGs := schema.CopySet(rawRemoteSgs.(*schema.Set))
					if len(remoteSGs.List()) > 0 {
						localSGs := l["security_groups"].(*schema.Set)
						if len(localSGs.List()) > len(remoteSGs.List()) {
							log.Printf("[DEBUG] Local rule has more Security Groups, continuing (%d/%d)", len(localSGs.List()), len(remoteSGs.List()))
							continue
						}

						// filter through the local security groups looking for the matching
						// security group id or name. Which shouldn't matter to us (name or
						// id)
						localRemaining := len(localSGs.List())
						// Security Groups we've found a match for.
						// if we've matched all of them (checked later), we'll add these
						// back to the local map since they are already in the []string
						// format we need them in
						var stringSGs []interface{}
						for _, lsg := range localSGs.List() {
							// for each match, pop the remote cidr from the list
							if remoteSGs.Contains(lsg) {
								log.Printf("[DEBUG] removing %s from remote SG set", lsg)
								remoteSGs.Remove(lsg)
								localRemaining--
								stringSGs = append(stringSGs, lsg)
							}
						}

						// if we've removed all the locals, establish the new set and add
						// this local rule to be returned
						if localRemaining == 0 {
							r["security_groups"] = remoteSGs
							l["security_groups"] = schema.NewSet(schema.HashString, stringSGs)
							saves = append(saves, l)
							continue
						}
					} else {
						log.Printf("[DEBUG] Remote Security Group length is zero")
					}
				} else {
					log.Printf("[DEBUG] No remote Security Group set")
				}

				// if we've reached this point, we have not found a match based on cidr
				// blocks and security groups.
				//
				// We have however matched on ports and type, but have not fully matched
				// on security groups or ports, we check the last remaining piece, which
				// is the self attribute. resourceAwsSecurityGroupIPPermGather does us
				// the favor of parsing this out of the security_groups set, so if self
				// is the only attribut set, there will be an empty remote security
				// groups.
				if _, ok := l["self"]; ok {
					if r["self"] == l["self"] {
						saves = append(saves, r)
					}
				}
			}
		}
	}

	// filter out "dead" remotes
	for _, r := range remote {
		if rCidrs, ok := r["cidr_blocks"]; ok {
			if len(rCidrs.([]string)) != 0 {
				log.Printf("[DEBUG] Found a remote CIDR block rule that wasn't empty: (%#v)", r)
				// convert/split as needed
				//
				// some method
				//
				// add what's left of remote to the saves
				saves = append(saves, r)
			}
		}

		if rawSGs, ok := r["security_groups"]; ok {
			rSGs := rawSGs.(*schema.Set)
			if len(rSGs.List()) != 0 {
				log.Printf("[DEBUG] Found a remote Security Group ID rule that wasn't empty: (%#v)", r)
				saves = append(saves, r)
			}
		}
	}

	return saves
}

// Creates a unique hash for the type, ports, and protocol, used as a key in
// maps
func idHash(rType, protocol string, toPort, fromPort int64, self bool) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s-", rType))
	buf.WriteString(fmt.Sprintf("%d-", toPort))
	buf.WriteString(fmt.Sprintf("%d-", fromPort))
	buf.WriteString(fmt.Sprintf("%s-", protocol))
	buf.WriteString(fmt.Sprintf("%t-", self))

	return fmt.Sprintf("rule-%d", hashcode.String(buf.String()))
}

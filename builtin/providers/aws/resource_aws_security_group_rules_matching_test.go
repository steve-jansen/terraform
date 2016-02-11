package aws

import (
	"log"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform/helper/schema"
)

// testing rulesForGroupPermissions
func TestRulesMatching(t *testing.T) {
	cases := []struct {
		groupId string
		local   []interface{}
		remote  []map[string]interface{}
		saves   []map[string]interface{}
	}{
		//  local and remote match
		{
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
			local: []interface{}{},
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

	for i, c := range cases {
		saves := matchRules("ingress", c.local, c.remote)
		if err != nil {
			t.Fatal(err)
		}
		log.Printf("\n\tTest %d:\n", i)

		if len(saves) != len(c.saves) {
			t.Fatalf("Expected %d saves, got %d", len(c.saves), len(saves))
		}

		shouldFind := len(c.saves)
		var found int
		for _, s := range saves {
			for _, cs := range c.saves {
				if reflect.DeepEqual(s, cs) {
					found++
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
								found++
							}
						}
					}
				}
			}
		}

		if found != shouldFind {
			t.Fatalf("Bad sg rule matches (%d / %d)", found, shouldFind)
		}
	}
}

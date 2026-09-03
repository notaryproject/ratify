/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package alibabacloud

import (
	"fmt"
	"regexp"
	"strings"
)

const acrNameSuffix = ".aliyuncs.com"

// domainPattern extracts the optional ACR Enterprise Edition instance name and
// the region from an Alibaba Cloud Registry host. The instance name is the
// label preceding "-registry" (empty for a shared registry). Examples:
//
//	registry.cn-hangzhou.cr.aliyuncs.com                 (shared registry, no instance name)
//	dahu-registry.cn-hangzhou.cr.aliyuncs.com            (EE instance "dahu")
//	dahu-registry-vpc.cn-hangzhou.cr.aliyuncs.com        (EE instance "dahu", VPC endpoint)
//
// The pattern is kept identical to the Ratify v1 implementation to preserve the
// same host-parsing behavior.
var domainPattern = regexp.MustCompile(
	`^(?:(?P<instanceName>[^.\s]+)-)?registry(?:-intl)?(?:-vpc)?(?:-internal)?(?:\.distributed)?\.(?P<region>[^.]+\-[^.]+)\.(?:cr\.)?aliyuncs\.com`)

// acrMetaInfo holds the instance name and region parsed from an ACR host.
type acrMetaInfo struct {
	instanceName string
	region       string
}

// parseACRHost parses the ACR Enterprise Edition instance name and region from
// a registry host.
func parseACRHost(host string) (*acrMetaInfo, error) {
	if !strings.HasSuffix(host, acrNameSuffix) {
		return nil, fmt.Errorf("invalid Alibaba Cloud Registry host %q which does not end with %q", host, acrNameSuffix)
	}
	subItems := domainPattern.FindStringSubmatch(host)
	if len(subItems) != 3 || subItems[2] == "" {
		return nil, fmt.Errorf("invalid Alibaba Cloud Registry host format %q", host)
	}
	return &acrMetaInfo{
		instanceName: subItems[1],
		region:       subItems[2],
	}, nil
}

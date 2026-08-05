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

	re "github.com/notaryproject/ratify/v2/errors"
)

const (
	acrNameSuffix   = ".aliyuncs.com"
	defaultInstance = "defaultInstance"
)

// examples of valid Alibaba Cloud Registry images:
// test-registry-vpc.cn-hangzhou.cr.aliyuncs.com
// test-registry.cn-hangzhou.cr.aliyuncs.com
var domainPattern = regexp.MustCompile(
	`^(?:(?P<instanceName>[^.\s]+)-)?registry(?:-intl)?(?:-vpc)?(?:-internal)?(?:\.distributed)?\.(?P<region>[^.]+\-[^.]+)\.(?:cr\.)?aliyuncs\.com`)

type AcrMetaInfo struct {
	InstanceName string
	Region       string
}

func getRegionFromArtifact(artifact string) (*AcrMetaInfo, error) {
	if !strings.HasSuffix(artifact, acrNameSuffix) {
		return nil, re.ErrorCodeAlibabaCloudImageInvalid.WithComponentType(re.AuthProvider).WithDetail(fmt.Sprintf("Invalid Alibaba Cloud Registry image %s which does not end with `aliyuncs.com`", artifact))
	}
	subItems := domainPattern.FindStringSubmatch(artifact)
	if len(subItems) != 3 {
		return nil, re.ErrorCodeAlibabaCloudImageInvalid.WithComponentType(re.AuthProvider).WithDetail("Invalid Alibaba Cloud Registry image format")
	}
	return &AcrMetaInfo{
		InstanceName: subItems[1],
		Region:       subItems[2],
	}, nil
}

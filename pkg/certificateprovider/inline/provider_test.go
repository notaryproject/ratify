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

package inline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCertificates(t *testing.T) {
	cases := []struct {
		desc          string
		parameters    map[string]string
		expectedErr   bool
		expectedCerts int
	}{
		{
			desc:        "value not provided",
			parameters:  map[string]string{},
			expectedErr: true,
		},
		{
			desc: "invalid certificate",
			parameters: map[string]string{
				"value": "-----BEGIN CERTIFICATE-----\nbaddata\n-----END CERTIFICATE-----\n",
			},
			expectedErr: true,
		},
		{
			desc: "single certificate",
			parameters: map[string]string{
				"value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n",
			},
			expectedCerts: 1,
		},
		{
			desc: "certificate chain",
			parameters: map[string]string{
				"value": "-----BEGIN CERTIFICATE-----\nMIIEeDCCAmCgAwIBAgIUbztxbi/gSPMZGN53oZQZW1h/lbAwDQYJKoZIhvcNAQEL\nBQAwazELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdSZWRtb25k\nMRMwEQYDVQQKDApNeSBDb21wYW55MQ8wDQYDVQQLDAZNeSBPcmcxFzAVBgNVBAMM\nDmNhLmV4YW1wbGUuY29tMB4XDTIzMDIwMTIyNTMxMFoXDTI0MDIwMTIyNTMxMFow\nbTEZMBcGA1UEAxMQbGVhZi5leGFtcGxlLmNvbTEPMA0GA1UECxMGTXkgT3JnMRMw\nEQYDVQQKEwpNeSBDb21wYW55MRAwDgYDVQQHEwdSZWRtb25kMQswCQYDVQQIEwJX\nQTELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCs\nMixf+WT34edYXs2c80zOg4Z/cxOVHU05gywjuISeaP+KS+Joc3emgbub1t5dPclk\nieIwrj3Olk3tvkrPiarOJIcrNR2zfBmQAufR4AUjoc4n1GQSp/voGgw1Hvh0wTkO\nYjhzLomrF242Ond8WTVO3Vq6/tfApfZMFM59eK9LMBkuvwTV4NeLnEnPvpLAoAvV\n9ZvCu7FuQ849R93Aoag2bZc3Tc3UCbahoJs9rTE/rnAqOhJWMGv2J1Y2Wu2eIvkD\n2uCmcVlY+7owG3TwLHTuIOBFl/5MXMvfR+B7yp1OkG23rTwwuSEBlMhYRzJFvssv\n8FX0sea7zhIg5dtoRjIlAgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG\n9w0BAQsFAAOCAgEANRUu+9aBAuRf3OsdUWJflMAvuyzREp3skWSOUs4dw0MhcB6x\nb7BSyNdrBgPImLBpqYzNU6IT2eIlLXrYnKLehvPyZQx7LHvIeompA09aKMFFesqi\ngVoW5GRtp3qL3oNuuZJ80r/uKlB6Cj51TWqUbLcctBGHX7TWxFeWmFRnN0Bki00U\nJW/ElaTsr4GB+ltgZM+5USUqSNQqTa8t3d+vH6oVikyV1oYunM41xAfiRZtID04z\no15sLSkWTjavfmZ3+NjllipXFY2tnLqymCcObgdKtJHmTMFSDRngDjY+3+RVj4EY\npNaCCCepvtmXz1C5f06tlgY4ofaautJuAL7K93p/Q9ZcsIhmYWkCUZ0dkWq+eMdT\n9/lB9rQHbrDTaRxEQNIUezFMQEBxR9eC5JQfpw98LobAgA3r4vizQjQPsN0UZ54h\ncAHiyoo1VeckkotXaToRsoLjixPO9Fmss4H3urJTLpcU0drbVoG3emNh4K289vgR\nrjV11TenqvvR3+jJ2AX2ewSsF25m0afheZbrq2ZtyITPAbOqwMwTbTOvJT3HUztt\nhUP3qwsKNPR/hF3FSqZewiYOSqJi5Dk28Vd6mUEQzZa/Ma9RpBR+BAmfgH3Z9gX5\n0TqmAVQn1P8yh+bhEjiNa20bTJ+y5vQ9OrA7fiQ+6vpZCio4NFiEbYK4UBI=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFxzCCA6+gAwIBAgIUY1fnGcYJFIGNk8fevKdGtOuZ5vcwDQYJKoZIhvcNAQEL\nBQAwazELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdSZWRtb25k\nMRMwEQYDVQQKDApNeSBDb21wYW55MQ8wDQYDVQQLDAZNeSBPcmcxFzAVBgNVBAMM\nDmNhLmV4YW1wbGUuY29tMB4XDTIzMDIwMTIyNTIwN1oXDTMzMDEyOTIyNTIwN1ow\nazELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdSZWRtb25kMRMw\nEQYDVQQKDApNeSBDb21wYW55MQ8wDQYDVQQLDAZNeSBPcmcxFzAVBgNVBAMMDmNh\nLmV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtQXd\n+qySVVMHx7iGz9xRdpDKb+zATK3asMFnMXWBn0MCkcOMJvhjajA8yrCpfMudjiW0\nReQ6xcjEfnJqkzwxrK7tPE9cQ6JzQGCxsmscRzKf1NoJL2ske5xBteKuJhSfZ9la\ncIZn/EU2F6eMAl9U4Y+ncIIrl4UoB5H/AJJj62WMl5QAvzXXwCBwlLHQe4/T3Axu\n9xmD3HTC7iQExOUFLdJx86fK3ym0futi1RgOUgD+OrnyDEIkD8mGxffPYPgszS71\nUuJX+NTsLZ/JW3ER/PMAPnBsMsMTTxEIGnrp1CXf2RnwQnDHVsxZFMgkLTS6dksT\nTGevnulTNtVvSKsZ7MpzE01j7zDie4V4dQJzBJMktbeVq9KRoPIEX0WcKpg8bGS8\nd5p5pr+Lu/NOv6ur+av8M649qCPwJAv5i2P6ggT4YMNtY0wMD2kjcHJ9/l2gYpZj\n3DG0Hy3Xo8uKUmTSC7iGhLsSjleNhJkKyh3RCsuMKB9juE4qeXPoaoPWBIuarbkq\neVVZJu2PlgN8UcxM/ym+9GNJIfNJ18WGWm+5P3IDvfBbJ39yvzZlG2czju4BUzYn\nlPOHA/Z18TxZhlPrPVnyKSVbeg7sW17yMUI2LCeaFIOYdIFvM09RaCyLIGrQwhpe\nkLh56xXk702oNHaLxyh/v5kz8EyxnpXIlDntis0CAwEAAaNjMGEwHQYDVR0OBBYE\nFCESfoahHMx7GyBdTBARen7mc37nMB8GA1UdIwQYMBaAFCESfoahHMx7GyBdTBAR\nen7mc37nMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\nDQEBCwUAA4ICAQBst1MbRJd3FLSY36qaNuDhGncvcXIcYqP2A/SXVhjuAhVOTsrE\nejDYBSkjfxCgoA3LZnQLTcbcPwRL5dTBEvqBqzbyArOjc+G3kbjOeuZYv09M8kUU\nYG1bVnxXV17GMk7zcBUnr1iwnp4E0pzB9gTv+Jv1oV+EtAHe5QOTOmW9mm2SUXbH\nmIya+KlzkIgVJJ8kiGOyXsr8i4wpyDXZf720tqTzPQFTf6rUXo9PhYzOWrrj8c7V\n+bmJurV3XkgvdOiwNase17wXUG9Ad8FhVYpUicq3Csfx5M87IXUIlx51AxaOQK3G\n3skyJyAm8R8pHzhcsEuVV7bGZlbFPZeWAHpbIEwpKHlLoN6qMINk2kEbcVahL2Mu\nXBUcvJdO2LbmEvfS+1imr32YbJ5Ufetru+G4mwAp6a0P6u5FU8lbE1ZoFHhflsVq\nErvOcRKhKjAim4iwIVGS55Xyx1IpF7YSTYpL89vlMmaJsssEoCQAkf+lxmC3eEuy\n2kBu3QB3cUHZXJK+01krC5MqeHcEVuc/fbNcTsCBp+RYXNRjYsp6IzGjqltUfInE\n3Tywg3P0ZLPO06WLNjNeAFZw6T8yV5gLcTJ1xc5pEf4UiY1uCf4NmDpeWhT+vvto\n2AxC/+7x7EkEfZnYiD6tcyHyY+iuroptws8lc5wRis859kydnq3vtxbXPQ==\n-----END CERTIFICATE-----\n",
			},
			expectedCerts: 2,
		},
	}

	provider := Create()

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			certs, _, err := provider.GetCertificates(context.TODO(), tc.parameters)

			assert.Equal(t, tc.expectedErr, err != nil)
			assert.Equal(t, tc.expectedCerts, len(certs))
		})
	}
}


import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJUYOHTaouFm1YMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi0tdXdnZjNzYy51cy5hdXRoMC5jb20wHhcNMjIwNzIxMTU1NDIwWhcN
MzYwMzI5MTU1NDIwWjAkMSIwIAYDVQQDExlkZXYtLXV3Z2Yzc2MudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4m+ebI0TVEYDTuHa
8c//q9dlJoIZ4wc6mz9d2A5U9kzHQLUkK7c7NZRTNtRCQgvYc9qUacxLQGVkKzDR
IyHIqGE9FOnU9bWFS+kO+ic3a7v15g2QiX6mzK67dOpjwmt3dypIADmNpsO2QXA0
Nxk27LNsJ+YZtt5MMZWXnbwQw0lrpCisiofSMWoCPFsGBedQeq86nuZk3ybe4ZRA
S0CHcks1Dq9fn+NyLB2S0dsxIoTxDrfZMv1fuLoSKixT8U1h8ObcwIVfhJ1gwg6M
/3oyZi+WSSVgFa9eTPgFWdEsGBDWW9SOgpL4Y+Tnsck5e75t8Bt/X7G8q8w2wt0J
Vosh4wIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSQ7JTAHgKY
i6vZ0PIVhH0YcZ29XzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AF7r8bcP414yBb+Exu9FcvSchFl0erIE1Mqr/pxo+Zmx10oi7px9N2ZUfQEn3bE1
t5o3daepkB12xXbx52uS0wMNTci0nHTdn1+P5MD2zinB+YKAWKr67ASs+5gjgt5d
8d8kBRDDyr263NRel8uU9+5KuJByHq8ttfFZXSU3BPDXSx+Hbv0Ux8aMeWAOYmBJ
NAKWZrwZuIt1lrszfCOUJIn5PNIiRk8Wna19UItZNo5cYb/YFKf9nQouIDPa8M+W
hkKEVZsan3qkv83uPkZOML5J7kRJMqA1sTIMJLrdp6tbXKVivqnlHNpU6GmrZi1X
xcasafc5tHflVirmB+ms8W8=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}

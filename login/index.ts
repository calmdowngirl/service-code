import { APIGatewayProxyEventV2 } from 'aws-lambda'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
// import * as querystring from 'querystring'
import { readFileSync } from 'fs'
import { dynamo, dynamoQueryPromise, toReturn, PATTERNS } from './shared'

interface TokenPayload {
  email: string
  token: string
  // iat: number
  // exp: number
}

export const handler = async (event: APIGatewayProxyEventV2) => {
  console.log(event)
  if (
    event.requestContext.http.method !== 'POST' ||
    event.headers['content-type'] !== 'application/x-www-form-urlencoded' ||
    !event.body
  )
    return toReturn(400)

  try {
    // var { id, password } = querystring.parse(atob(event.body))
    const formData = atob(event.body)
      .split('&')
      .reduce((acc, pair) => {
        const [key, value] = pair.split('=')
        acc[key] = decodeURIComponent(value)
        return acc
      }, {} as any)
    console.log(`### ${JSON.stringify(formData)}`)
    var { id, password } = formData
  } catch (e) {
    return toReturn(400)
  }

  try {
    if (!id || !PATTERNS.email.test(id) || !password) return toReturn(400)

    const params = {
      TableName: 'user',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: {
        ':email': { S: id },
      },
    }
    const item = (await dynamoQueryPromise(params))?.[0]
    console.log(item)
    if (!item) return toReturn(403, 'Invalid Account or Password')

    const exp = parseInt(item.exp_at.N)
    if (exp !== -1 && exp - Date.now() <= 0)
      return toReturn(403, 'Account Expired')

    const hashedPwd = await bcrypt.hash(password as string, item.salt.S)
    if (item.password.S !== hashedPwd) return toReturn(403)

    const secret = readFileSync('./shared/secret', 'utf-8')
    const payload1: TokenPayload = {
      email: item.email.S,
      token: await bcrypt.genSalt(1),
    }
    const payload2: TokenPayload = {
      email: item.email.S,
      token: await bcrypt.genSalt(1),
    }
    const accessToken = jwt.sign(payload1, secret, { expiresIn: 60 * 120 }) // 2h
    const refreshToken = jwt.sign(payload2, secret, { expiresIn: '8h' })

    await dynamo.updateItem({
      TableName: 'user',
      Key: {
        email: { S: item.email.S },
        created_by: { S: item.created_by.S },
      },
      UpdateExpression: 'set access_token = :val1, refresh_token = :val2',
      ExpressionAttributeValues: {
        ':val1': { S: payload1.token },
        ':val2': { S: payload2.token },
      },
    })

    return toReturn(
      200,
      JSON.stringify({ accessToken, refreshToken, role: item.role.S })
    )
  } catch (e) {
    console.log(e)
    return toReturn(500)
  }
}

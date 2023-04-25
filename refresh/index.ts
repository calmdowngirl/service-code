import { APIGatewayProxyEvent } from 'aws-lambda'
import { DynamoDB, GetItemInput } from '@aws-sdk/client-dynamodb'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
import { readFileSync } from 'fs'

interface TokenPayload {
  email: string
  token: string
}

const region = 'ap-southeast-2'
const dynamo = new DynamoDB({ region })

export const handler = async (event: APIGatewayProxyEvent) => {
  if (event.httpMethod !== 'GET' || event.path !== '/refresh')
    return toReturn(400)

  try {
    const token = event.headers?.['token']
    console.log(`### ${token}`)
    const secret = readFileSync('./secret', 'utf-8')
    if (!token || !secret) return toReturn(403)

    let decodedToken
    try {
      decodedToken = jwt.verify(token, secret) as TokenPayload
      console.log(decodedToken)
    } catch (e) {
      console.log(e)
      if (e instanceof jwt.TokenExpiredError)
        return toReturn(403, 'Refresh Token Expired')
      if (e instanceof jwt.JsonWebTokenError) return toReturn(403)
    }

    const params = {
      TableName: 'user',
      Key: {
        email: { S: (decodedToken as TokenPayload).email },
        sort_key: { S: (decodedToken as TokenPayload).email },
      },
    }
    const item = await dynamoGetItemPromise(params)
    console.log(item)

    const payload1: TokenPayload = {
      email: item.email.S,
      token: await bcrypt.genSalt(1),
    }
    const payload2: TokenPayload = {
      email: item.email.S,
      token: await bcrypt.genSalt(1),
    }
    const accessToken = jwt.sign(payload1, secret, { expiresIn: '15' })
    const refreshToken = jwt.sign(payload2, secret, { expiresIn: '3h' })

    await dynamo.updateItem({
      TableName: 'user',
      Key: {
        email: { S: item.email.S },
        sort_key: { S: item.email.S },
      },
      UpdateExpression: 'set access_token = :val1, refresh_token = :val2',
      ExpressionAttributeValues: {
        ':val1': { S: payload1.token },
        ':val2': { S: payload2.token },
      },
    })

    return toReturn(200, JSON.stringify({ accessToken, refreshToken }))
  } catch (e) {
    console.log(e)
    return toReturn(500)
  }
}

function dynamoGetItemPromise(
  params: GetItemInput
): Promise<DynamoDB.AttributeMap> {
  return new Promise((resolve, reject) => {
    dynamo.getItem(params, (err: any, data: any) => {
      if (err) reject(err)
      else resolve(data.Item)
    })
  })
}

function toReturn(code: number, body?: string) {
  if (body) body = JSON.stringify(body)
  const contentType = body && code === 200 ? 'application/json' : 'text/plain'

  switch (code) {
    case 400:
      body = JSON.stringify('Bad Request')
      break
    case 403:
      body = body || JSON.stringify('Forbidden')
      break
    case 500:
      body = body || JSON.stringify('Server Error')
      break
    case 200:
      if (body) body = JSON.parse(body)
      else body = JSON.stringify('Ok')
      break
    default:
      body = body || JSON.stringify('hello')
  }

  const response = {
    headers: {
      'Content-Type': contentType,
    },
    statusCode: code,
    body,
  }

  return response
}

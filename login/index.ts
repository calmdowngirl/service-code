/**
 * doc
 *
 * [access token]
 * allow user to access api, lifespan default to 15 mins
 *
 */

import { APIGatewayProxyEvent } from 'aws-lambda'
import { DynamoDB } from '@aws-sdk/client-dynamodb'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
import { readFileSync } from 'fs'
import * as querystring from 'querystring'

interface TokenPayload {
  email: string
  token: string
  // iat: number
  // exp: number
}

const region = 'ap-southeast-2'
const dynamo = new DynamoDB({ region })

export const handler = async (event: APIGatewayProxyEvent) => {
  if (event.httpMethod !== 'POST' || event.path !== '/login' || !event.body)
    return toReturn(400)

  try {
    const query = querystring.parse(event.body!!)

    // todo
    //- [] data validation check

    const id = query.id || false
    const pwd = query.password || false

    if (!id || !pwd) return toReturn(400)

    const params = {
      TableName: 'user',
      Key: {
        email: { S: id },
        sort_key: { S: id },
      },
    }
    const item = await dynamoGetItemPromise(params)
    console.log(item)

    const hashedPwd = await bcrypt.hash(pwd as string, item.salt.S)
    if (item.password.S !== hashedPwd) return toReturn(403)

    const secret = readFileSync('./secret', 'utf-8')

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
  params: DynamoDB.GetItemInput
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

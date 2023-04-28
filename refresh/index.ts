import { APIGatewayProxyEvent } from 'aws-lambda'
import { DynamoDB, GetItemInput } from '@aws-sdk/client-dynamodb'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
import { readFileSync } from 'fs'
import { region, dynamo, dynamoGetItemPromise, toReturn } from './shared'

interface TokenPayload {
  email: string
  token: string
}

export const handler = async (event: APIGatewayProxyEvent) => {
  if (event.httpMethod !== 'GET' || event.path !== '/refresh')
    return toReturn(400)

  try {
    const token = event.headers?.['token']
    console.log(`### ${token}`)
    const secret = readFileSync('./shared/secret', 'utf-8')
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

    if (item.refresh_token.S !== (decodedToken as TokenPayload).token)
      return toReturn(403)

    const payload1: TokenPayload = {
      email: item.email.S,
      token: await bcrypt.genSalt(1),
    }
    const payload2: TokenPayload = {
      email: item.email.S,
      token: await bcrypt.genSalt(1),
    }
    const accessToken = jwt.sign(payload1, secret, { expiresIn: 60 * 120 })
    const refreshToken = jwt.sign(payload2, secret, { expiresIn: '8h' })

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

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

const region = 'ap-southeast-2'
const dynamo = new DynamoDB({ region })
const allowedRoles = ['su', 'admin']
const allowedInputRoles = ['admin', 'consumer']

export const handler = async (event: APIGatewayProxyEvent) => {
  if (
    event.httpMethod !== 'PUT' ||
    event.path !== '/create-user' ||
    !event.body
  )
    return toReturn(400)

  try {
    const input = JSON.parse(event.body)

    /// todo
    //- [] data validation check

    const secret = readFileSync('./shared/secret', 'utf-8')

    const token = event.headers?.['token']
    console.log(`### ${token}`)
    if (!token || !secret) return toReturn(403)

    let decodedToken
    try {
      decodedToken = jwt.verify(token, secret) as TokenPayload
      console.log(decodedToken)
    } catch (e) {
      console.log(e)
      if (e instanceof jwt.TokenExpiredError)
        return toReturn(403, 'Session Expired')
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

    if (item.access_token.S !== (decodedToken as TokenPayload).token)
      return toReturn(403)
    if (input.role === 'su') return toReturn(403)
    if (item.role.S === input.role || item.role.S === 'consumer')
      return toReturn(403)
    if (item.role.S === 'admin' && input.role !== 'consumer')
      return toReturn(403)

    const password = input.password
    const salt = await bcrypt.genSalt(1)
    const hashedPwd = await bcrypt.hash(password, salt)

    await dynamo.putItem({
      TableName: 'user',
      Item: {
        name: { S: input.name },
        email: { S: input.email },
        sort_key: { S: input.email },
        password: { S: hashedPwd },
        salt: { S: salt },
        role: { S: input.role },
        created_at: { N: Date.now().toString() },
        exp_at: { N: '-1' },
      },
    })

    return toReturn(200)
  } catch (e) {
    console.log(e)
    return toReturn(500)
  }
}

function revokeAccess() {
  /// todo
}

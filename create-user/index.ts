import { APIGatewayProxyEvent } from 'aws-lambda'
import { DynamoDB, GetItemInput } from '@aws-sdk/client-dynamodb'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
import { readFileSync } from 'fs'
import {
  region,
  dynamo,
  dynamoGetItemPromise,
  toReturn,
  PATTERNS,
} from './shared'

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
    console.log(`### payload ${event.body}`)
    var { email, role, name, password, phone, exp_at } = JSON.parse(event.body)
  } catch (e) {
    return toReturn(400, 'Invalid JSON')
  }

  try {
    if (allowedInputRoles.indexOf(role) === -1)
      return toReturn(400, 'Invalid role')
    if (!PATTERNS.email.test(email)) return toReturn(400, 'Invalid email')
    if (name && !PATTERNS.nameAllowSpaceAndDash.test(name))
      return toReturn(400, 'Invalid name')
    if (phone && !PATTERNS.phone.test(phone))
      return toReturn(400, 'Invalid phone')
    if (
      exp_at &&
      exp_at != '-1' &&
      !PATTERNS.digits.test(exp_at) &&
      Date.now() - exp_at <= 3600 * 1000
    )
      return toReturn(400, 'Invalid exp_at')

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
    if (role === 'su') return toReturn(403)
    if (item.role.S === role || item.role.S === 'consumer') return toReturn(403)
    if (item.role.S === 'admin' && role !== 'consumer') return toReturn(403)

    const putItem = { TableName: 'user', Item: {} as any }
    putItem.Item.email = { S: email }
    putItem.Item.sort_key = { S: email }
    putItem.Item.role = { S: role }
    putItem.Item.created_at = { N: Date.now().toString() }
    putItem.Item.exp_at = { N: exp_at?.toString() ?? '-1' }
    if (name) putItem.Item.name = { S: name }
    if (password) {
      const salt = await bcrypt.genSalt(1)
      const hashedPwd = await bcrypt.hash(password, salt)
      putItem.Item.password = { S: hashedPwd }
      putItem.Item.salt = { S: salt }
    }
    await dynamo.putItem(putItem)
    return toReturn(200)
  } catch (e) {
    console.log(e)
    return toReturn(500)
  }
}

function revokeAccess() {
  /// todo
}

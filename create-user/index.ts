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
const PATTERNS = {
  nameAllowSpaceAndDash: /^[\w]+([\s-]?\w)+$/,
  nameNoSpaceOrDash: /^[\w]*$/,
  digits: /^\d*$/,
  rationalNumber: /^[+-]?(\d+[.])?\d+$/,
  phone: /^[+]?\d{3,15}$/,
  noExecutable: /^[^`'"<>]+$/,
  email:
    // eslint-disable-next-line no-useless-escape
    /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
  resetCode: /[a-zA-Z0-9]{6}/,
}

export const handler = async (event: APIGatewayProxyEvent) => {
  if (
    event.httpMethod !== 'PUT' ||
    event.path !== '/create-user' ||
    !event.body
  )
    return toReturn(400)

  try {
    // const input = JSON.parse(event.body)
    const { email, role, name, password, phone, exp_at } = JSON.parse(
      event.body
    )

    /// todo
    //- [] data validation check
    if (!allowedInputRoles.includes(role) || !PATTERNS.email.test(email))
      return toReturn(403)
    if (name && !PATTERNS.nameAllowSpaceAndDash.test(name)) return toReturn(403)
    if (phone && !PATTERNS.phone.test(phone)) return toReturn(403)
    // if (exp_at)

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
    if (name) putItem.Item.name = { S: name }
    if (password) {
      const salt = await bcrypt.genSalt(1)
      const hashedPwd = await bcrypt.hash(password, salt)
      putItem.Item.password = { S: hashedPwd }
      putItem.Item.salt = { S: salt }
    }
    if (exp_at) putItem.Item.name = { N: exp_at }

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

import { APIGatewayProxyEvent } from 'aws-lambda'
import { DynamoDB } from '@aws-sdk/client-dynamodb'
import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
import { readFileSync } from 'fs'

interface TokenPayload {
  email: string
}

const region = 'ap-southeast-2'
const dynamo = new DynamoDB({ region })

exports.handler = async (event: APIGatewayProxyEvent) => {
  const response = {
    statusCode: 403,
    body: JSON.stringify('Unauthorised'),
    headers: {
      'Content-Type': 'application/json',
    },
  }

  try {
    if (event.httpMethod === 'PUT' && event.path === '/create-user') {
      const input = JSON.parse(event.body ?? '{}')
      let secret: string = readFileSync('./secret', 'utf-8')

      const token = event.headers?.['token']
      if (!token || !secret) return response

      let decodedToken
      try {
        decodedToken = jwt.verify(token, secret) as TokenPayload
      } catch (e) {
        console.log(e)
        return response
      }

      await dynamo.getItem({
        TableName: 'user',
        Key: {
          email: { S: decodedToken.email },
        },
      })

      // todo: isAuthorised
      // todo: data validation check

      const password = input.password
      const salt = await bcrypt.genSalt(5)
      const hashedPwd = await bcrypt.hash(password, salt)

      await dynamo.putItem({
        TableName: 'user',
        Item: {
          name: { S: input.name },
          email: { S: input.email },
          password: { S: hashedPwd },
          salt: { S: salt },
          role: { S: input.role },
          created_at: { N: Date.now().toString() },
          exp_at: { N: '-1' },
        },
      })

      response.body = JSON.stringify('Ok')
    } else {
      response.statusCode = 400
      response.body = JSON.stringify('Bad Request')
    }
  } catch (e) {
    console.log(e)
    response.statusCode = 500
    response.body = JSON.stringify('Server Error')
  }

  response.statusCode = 200
  response.body = JSON.stringify('Ok')

  return response
}

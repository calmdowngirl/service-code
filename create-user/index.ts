import { APIGatewayProxyEvent } from 'aws-lambda'
import { DynamoDB } from '@aws-sdk/client-dynamodb'
import * as bcrypt from 'bcryptjs'

const region = 'ap-southeast-2'
const dynamo = new DynamoDB({ region })

exports.handler = async (event: APIGatewayProxyEvent) => {
  const response = {
    statusCode: 200,
    body: JSON.stringify('Hello from Lambda!'),
    headers: {
      'Content-Type': 'application/json',
    },
  }

  try {
    if (event.httpMethod === 'PUT' && event.path === '/create-user') {
      const input = JSON.parse(event.body ?? '{}')

      // todo: isAuthorised
      // todo: data validation check

      const password = input.password
      const salt = await bcrypt.genSalt(5)
      const hashedPwd = await bcrypt.hash(password, salt)
      console.log(salt, hashedPwd)
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
      ;(response.statusCode = 400),
        (response.body = JSON.stringify('Bad Request'))
    }
  } catch (e) {
    console.log(e)
    ;(response.statusCode = 500),
      (response.body = JSON.stringify('Server Error'))
  }

  return response
}

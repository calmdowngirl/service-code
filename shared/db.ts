import { DynamoDB, GetItemInput, QueryInput } from '@aws-sdk/client-dynamodb'

export const region = 'ap-southeast-2'
export const dynamo = new DynamoDB({ region })

export const dynamoGetItemPromise = (params: GetItemInput) => {
  return new Promise((resolve, reject) => {
    dynamo.getItem(params, (err: any, data: any) => {
      if (err) reject(err)
      else resolve(data.Item)
    })
  })
}

export const dynamoQueryPromise = (params: QueryInput) => {
  return new Promise((resolve, reject) => {
    dynamo.query(params, (err: any, data: any) => {
      if (err) reject(err)
      else resolve(data.Items)
    })
  })
}

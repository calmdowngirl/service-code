import { DynamoDB, GetItemInput } from '@aws-sdk/client-dynamodb'

export const region = 'ap-southeast-2'
export const dynamo = new DynamoDB({ region })

export const dynamoGetItemPromise = (
  params: GetItemInput
): Promise<DynamoDB.AttributeMap> => {
  return new Promise((resolve, reject) => {
    dynamo.getItem(params, (err: any, data: any) => {
      if (err) reject(err)
      else resolve(data.Item)
    })
  })
}

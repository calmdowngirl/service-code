export const toReturn = (code: number, body?: string) => {
  if (body) body = JSON.stringify(body)
  const contentType = body && code === 200 ? 'application/json' : 'text/plain'

  switch (code) {
    case 400:
      body = body || JSON.stringify('Bad Request')
      break
    case 403:
      body = body || JSON.stringify('Forbidden')
      break
    case 500:
      body = body || JSON.stringify('Error')
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
      'Access-Control-Allow-Headers':
        'Content-Type,token,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
      // 'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': '*',
      'X-Requested-With': '*',
    },
    statusCode: code,
    body,
  }

  return response
}

export const randomString = (len: number) => {
  const randomInt = (max: number) => Math.floor(Math.random() * max)
  const randomShortStr = () =>
    Math.random().toString(36).replace('.', '').toUpperCase()

  let s = ''
  for (let i = 0; i < 10; i++) s += randomShortStr()
  const rl = s.length
  const fromIdx = randomInt(rl - 1 - len)
  return s.substring(fromIdx, fromIdx + len)
}

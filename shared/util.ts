export const toReturn = (code: number, body?: string) => {
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

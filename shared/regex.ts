export const PATTERNS = {
  nameAllowSpaceAndDash: /^[\w]+([\s-]?\w)+$/,
  nameNoSpaceOrDash: /^[\w]*$/,
  digits: /^\d+$/,
  rationalNumber: /^[+-]?(\d+[.])?\d+$/,
  phone: /^[+]?\d{3,15}$/,
  noExecutable: /^[^`'"<>]+$/,
  email:
    /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
  resetCode: /[a-zA-Z0-9]{6}/,
}

"use strict";
/**
 * doc
 *
 * [access token]
 * allow user to access api, lifespan default to 15 mins
 *
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.handler = void 0;
var client_dynamodb_1 = require("@aws-sdk/client-dynamodb");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
var fs_1 = require("fs");
var querystring = require("querystring");
var region = 'ap-southeast-2';
var dynamo = new client_dynamodb_1.DynamoDB({ region: region });
var handler = function (event) { return __awaiter(void 0, void 0, void 0, function () {
    var query, id, pwd, params, item, hashedPwd, secret, payload1, payload2, accessToken, refreshToken, e_1;
    var _a, _b;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                if (event.httpMethod !== 'POST' || event.path !== '/login' || !event.body)
                    return [2 /*return*/, toReturn(400)];
                _c.label = 1;
            case 1:
                _c.trys.push([1, 7, , 8]);
                query = querystring.parse(event.body);
                id = query.id || false;
                pwd = query.password || false;
                if (!id || !pwd)
                    return [2 /*return*/, toReturn(400)];
                params = {
                    TableName: 'user',
                    Key: {
                        email: { S: id },
                        sort_key: { S: id }
                    }
                };
                return [4 /*yield*/, dynamoGetItemPromise(params)];
            case 2:
                item = _c.sent();
                console.log(item);
                return [4 /*yield*/, bcrypt.hash(pwd, item.salt.S)];
            case 3:
                hashedPwd = _c.sent();
                if (item.password.S !== hashedPwd)
                    return [2 /*return*/, toReturn(403)];
                secret = (0, fs_1.readFileSync)('./secret', 'utf-8');
                _a = {
                    email: item.email.S
                };
                return [4 /*yield*/, bcrypt.genSalt(1)];
            case 4:
                payload1 = (_a.token = _c.sent(),
                    _a);
                _b = {
                    email: item.email.S
                };
                return [4 /*yield*/, bcrypt.genSalt(1)];
            case 5:
                payload2 = (_b.token = _c.sent(),
                    _b);
                accessToken = jwt.sign(payload1, secret, { expiresIn: '15' });
                refreshToken = jwt.sign(payload2, secret, { expiresIn: '3h' });
                return [4 /*yield*/, dynamo.updateItem({
                        TableName: 'user',
                        Key: {
                            email: { S: item.email.S },
                            sort_key: { S: item.email.S }
                        },
                        UpdateExpression: 'set access_token = :val1, refresh_token = :val2',
                        ExpressionAttributeValues: {
                            ':val1': { S: payload1.token },
                            ':val2': { S: payload2.token }
                        }
                    })];
            case 6:
                _c.sent();
                return [2 /*return*/, toReturn(200, JSON.stringify({ accessToken: accessToken, refreshToken: refreshToken }))];
            case 7:
                e_1 = _c.sent();
                console.log(e_1);
                return [2 /*return*/, toReturn(500)];
            case 8: return [2 /*return*/];
        }
    });
}); };
exports.handler = handler;
function dynamoGetItemPromise(params) {
    return new Promise(function (resolve, reject) {
        dynamo.getItem(params, function (err, data) {
            if (err)
                reject(err);
            else
                resolve(data.Item);
        });
    });
}
function toReturn(code, body) {
    if (body)
        body = JSON.stringify(body);
    var contentType = body && code === 200 ? 'application/json' : 'text/plain';
    switch (code) {
        case 400:
            body = JSON.stringify('Bad Request');
            break;
        case 403:
            body = body || JSON.stringify('Unauthorised');
            break;
        case 500:
            body = body || JSON.stringify('Server Error');
            break;
        case 200:
            if (body)
                body = JSON.parse(body);
            else
                body = JSON.stringify('Ok');
        default:
            body = body || JSON.stringify('hello');
    }
    var response = {
        headers: {
            'Content-Type': contentType
        },
        statusCode: code,
        body: body
    };
    return response;
}

"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = void 0;
var client_dynamodb_1 = require("@aws-sdk/client-dynamodb");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
var fs_1 = require("fs");
var region = 'ap-southeast-2';
var dynamo = new client_dynamodb_1.DynamoDB({ region: region });
var handler = function (event) { return __awaiter(void 0, void 0, void 0, function () {
    var input, secret, token, decodedToken, params, item, password, salt, hashedPwd, e_1;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                if (event.httpMethod !== 'PUT' ||
                    event.path !== '/create-user' ||
                    !event.body)
                    return [2 /*return*/, toReturn(400)];
                _b.label = 1;
            case 1:
                _b.trys.push([1, 6, , 7]);
                input = JSON.parse(event.body);
                secret = (0, fs_1.readFileSync)('./secret', 'utf-8');
                token = (_a = event.headers) === null || _a === void 0 ? void 0 : _a['token'];
                console.log("### ".concat(token));
                if (!token || !secret)
                    return [2 /*return*/, toReturn(403)];
                decodedToken = void 0;
                try {
                    decodedToken = jwt.verify(token, secret);
                    console.log(decodedToken);
                }
                catch (e) {
                    console.log(e);
                    if (e instanceof jwt.TokenExpiredError)
                        return [2 /*return*/, toReturn(403, 'Session Expired')];
                    if (e instanceof jwt.JsonWebTokenError)
                        return [2 /*return*/, toReturn(403)];
                }
                params = {
                    TableName: 'user',
                    Key: {
                        email: { S: decodedToken.email },
                        sort_key: { S: decodedToken.email },
                    },
                };
                return [4 /*yield*/, dynamoGetItemPromise(params)];
            case 2:
                item = _b.sent();
                console.log(item);
                /// todo
                //- [done] check access token is the same
                //- [done] check if user role is sufficient for the request
                if (item.access_token.S !== decodedToken.token)
                    return [2 /*return*/, toReturn(403)];
                if (input.role === 'su')
                    return [2 /*return*/, toReturn(403)];
                if (item.role.S === input.role || item.role.S === 'consumer')
                    return [2 /*return*/, toReturn(403)];
                if (item.role.S === 'admin' && input.role !== 'consumer')
                    return [2 /*return*/, toReturn(403)];
                password = input.password;
                return [4 /*yield*/, bcrypt.genSalt(5)];
            case 3:
                salt = _b.sent();
                return [4 /*yield*/, bcrypt.hash(password, salt)];
            case 4:
                hashedPwd = _b.sent();
                return [4 /*yield*/, dynamo.putItem({
                        TableName: 'user',
                        Item: {
                            name: { S: input.name },
                            email: { S: input.email },
                            sort_key: { S: input.email },
                            password: { S: hashedPwd },
                            salt: { S: salt },
                            role: { S: input.role },
                            created_at: { N: Date.now().toString() },
                            exp_at: { N: '-1' },
                        },
                    })];
            case 5:
                _b.sent();
                return [2 /*return*/, toReturn(200)];
            case 6:
                e_1 = _b.sent();
                console.log(e_1);
                return [2 /*return*/, toReturn(500)];
            case 7: return [2 /*return*/];
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
            body = body || JSON.stringify('Forbidden');
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
            'Content-Type': contentType,
        },
        statusCode: code,
        body: body,
    };
    return response;
}

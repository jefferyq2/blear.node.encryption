/**
 * 加密
 * @author ydr.me
 * @create 2014-11-17 11:18
 */

'use strict';

var fs = require('fs');
var crypto = require('crypto');
var random = require('blear.utils.random');
var typeis = require('blear.utils.typeis');
var access = require('blear.utils.access');
var number = require('blear.utils.number');
var string = require('blear.utils.string');
var date = require('blear.utils.date');
var bigInt = require('big-integer');

var regExist = /[aA0]/g;
// ！！！
// 重要：字母、数字顺序一经确定就不能再二次变化
// ！！！
var dictionaryMap = {
    a: 'dapkrwxmynsjhbflngiqozucet',
    A: 'UWMGQXLAHFTSCRNNZJIOBYDKPE',
    0: '7412603958'
};


/**
 * 字符串的 MD5 计算
 * @param data {*} 待计算的数据
 * @returns {string}
 */
exports.md5 = function (data) {
    try {
        return crypto.createHash('md5').update(data).digest('hex');
    } catch (err) {
        /* istanbul ignore next */
        return '';
    }
};


/**
 * 字符串 sha1 加密
 * @param data {*} 实体
 * @param [secret] {*} 密钥，可选
 * @returns {*}
 */
exports.sha1 = function (data, secret) {
    if (arguments.length === 2) {
        try {
            return crypto.createHmac('sha1', String(secret)).update(data).digest('hex');
        } catch (err) {
            /* istanbul ignore next */
            return '';
        }
    } else {
        try {
            return crypto.createHash('sha1').update(data).digest('hex');
        } catch (err) {
            /* istanbul ignore next */
            return err.message;
        }
    }
};


/**
 * 文件内容的 etag 计算
 * @param file {String} 文件绝对路径
 * @param [callback] {Function} 读取文件流进行MD5计算
 * @returns {string}
 */
exports.etag = function (file, callback) {
    var md5;
    var stream;
    var data;

    if (typeis.Function(callback)) {
        md5 = crypto.createHash('md5');
        stream = fs.createReadStream(file);
        stream.on('data', function (d) {
            md5.update(d);
        });
        stream.on('end', function () {
            var d = md5.digest('hex');

            callback(null, d);
        });
        stream.on('error', callback);
    } else {
        try {
            data = fs.readFileSync(file);
        } catch (err) {
            /* istanbul ignore next */
            data = '';
        }

        return exports.md5(data);
    }
};


/**
 * 文件最后修改时间的 md5 计算
 * @param file {String} 文件绝对路径
 * @returns {string} md5 值
 */
exports.lastModified = function (file) {
    var stats;
    var ret;

    try {
        stats = fs.statSync(file);
    } catch (err) {
        /* istanbul ignore next */
        stats = null;
    }

    ret = stats ? String(new Date(stats.mtime).getTime()) : '0';

    return exports.md5(ret);
};


/**
 * 编码
 * @param data {String} 原始数据
 * @param secret {String} 密钥
 * @returns {String}
 */
exports.encode = function (data, secret) {
    var cipher = crypto.createCipher('aes192', String(secret));

    try {
        return cipher.update(String(data), 'utf8', 'hex') + cipher.final('hex');
    } catch (err) {
        /* istanbul ignore next */
        return '';
    }
};


/**
 * 解码
 * @param data {String} 编码后的数据
 * @param secret {String} 密钥
 * @returns {String}
 */
exports.decode = function (data, secret) {
    var decipher = crypto.createDecipher('aes192', String(secret));

    try {
        return decipher.update(String(data), 'hex', 'utf8') + decipher.final('utf8');
    } catch (err) {
        /* istanbul ignore next */
        return '';
    }
};


var defaultUniqueLength = 8;
var execTime = Date.now();
var execOffset = 0;
/**
 * 生成随机不重复的字符串，建议最小长度为 16，如果不够
 * @param [minLength=12] {number} 最小长度
 * @param [dictionary] {string} 词典，默认 62 进制（A-Za-Z0-9）
 * @returns {string}
 *
 * @example
 * // 字典对应关系
 * // a => a-z
 * // A => A-Z
 * // 0 => 0-9
 */
exports.unique = function (minLength, dictionary) {
    var args = access.args(arguments);

    if (args.length === 1 && typeis.String(args[0])) {
        dictionary = args[0];
        minLength = defaultUniqueLength;
    }

    minLength = Math.max(number.parseInt(minLength, defaultUniqueLength), defaultUniqueLength);
    dictionary = String(dictionary || 'aA0');

    var pool = generatePool(dictionary);
    var now = Date.now();
    var unique = (now).toString();

    if (execTime === now) {
        execOffset++;
    } else {
        execOffset = 0;
        execTime = now;
    }

    unique += execOffset;
    unique = numberConvert(unique, pool);

    var length = unique.length;

    if (length < minLength) {
        unique = randomInsert(unique, minLength - length, dictionary);
    }

    return unique;
};


// ===================================
// ===================================
// ===================================
/**
 * 字符池
 * @param dictionary
 * @returns {string}
 */
function generatePool(dictionary) {
    var pool = '';
    if (dictionary.indexOf('a') > -1) {
        pool += dictionaryMap.a;
    }

    if (dictionary.indexOf('A') > -1) {
        pool += dictionaryMap.A;
    }

    if (dictionary.indexOf('0') > -1) {
        pool += dictionaryMap[0];
    }

    pool += dictionary.replace(regExist, '');
    return pool;
}


/**
 * 指定次数随机插入数值
 * @param string
 * @param times
 * @param dictionary
 * @returns {*}
 */
function randomInsert(string, times, dictionary) {
    var pool = random.string(times, dictionary);
    while (times--) {
        var pos = Math.random() > 0.5 ? 0 : string.length;
        var rnd = pool[times];
        string = string.slice(0, pos) + rnd + string.slice(pos);
    }
    return string;
}


/**
 * 任意数值任意进制转换
 * @param guid
 * @param pool
 * @returns {string}
 */
function numberConvert(guid, pool) {
    guid = bigInt(guid);
    // 任意进制转换
    var ret = [];
    var system = pool.length;
    var _cal = function () {
        var y = guid.mod(system);

        guid = guid.divide(system);
        ret.unshift(pool[y]);

        if (guid.gt(0)) {
            _cal();
        }
    };

    _cal();

    return ret.join('');
}




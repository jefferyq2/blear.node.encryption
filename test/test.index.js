/**
 * 测试 文件
 * @author ydr.me
 * @create 2016-05-17 12:13
 */


'use strict';

var expect = require('chai-jasmine').expect;
var encryption = require('../src/index.js');

describe('测试文件', function () {
    it('.md5', function () {
        expect(encryption.md5('123')).toEqual('202cb962ac59075b964b07152d234b70');
    });

    it('.sha1', function () {
        expect(encryption.sha1('123')).toEqual('40bd001563085fc35165329ea1ff5c5ecbdbbeef');
        expect(encryption.sha1('123', 'abc')).toEqual('be9106a650ede01f4a31fde2381d06f5fb73e612');
    });

    it('.etag', function (done) {
        expect(encryption.etag(__filename, function (err, ret) {
            if (err) {
                throw err;
            }

            expect(encryption.etag(__filename)).toEqual(ret);
            done();
        }));
    });

    it('.lastModified', function () {
        expect(encryption.lastModified(__filename).length).toEqual(32);
    });

    it('.encode/.decode', function () {
        var original = '123';
        var secret = 'abc';

        var a = encryption.encode(original, secret);
        var b = encryption.decode(a, secret);

        expect(b).toEqual(original);
    });

    it('.unique', function () {
        var uni;
        // var now = Date.now();
        // var times = 0;
        //
        // while (now === Date.now()) {
        //     encryption.unique();
        //     times++;
        // }
        //
        // console.log('1 ms执行 %d 次', times);

        uni = encryption.unique();
        console.log(uni, uni.length);
        uni = encryption.unique();
        console.log(uni, uni.length);

        uni = encryption.unique(20);
        console.log(uni, uni.length);
        uni = encryption.unique(20);
        console.log(uni, uni.length);

        uni = encryption.unique('a');
        console.log(uni, uni.length);

        uni = encryption.unique('A');
        console.log(uni, uni.length);

        uni = encryption.unique('0');
        console.log(uni, uni.length);

        uni = encryption.unique('`aA0~!@#$%^&*()_+-={}[]|\\:;\'",<.>/?');
        console.log(uni, uni.length);
    });
});


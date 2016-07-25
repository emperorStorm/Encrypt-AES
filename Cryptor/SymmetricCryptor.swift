//
//  SymmetricCryptor.swift
//  Cryptor
//          AES256加密 ＋ Base64加密
//  Created by mac on 16/7/19.
//  Copyright © 2016年 mac. All rights reserved.
//

import Foundation

enum SymmetricCryptorError: ErrorType {
    case MissingIV
    case CryptOperationFailed
    case WrongInputData
    case UnknownError
}
/**
 *加密方式:
 *  key->md5加密
 *          |
 *  明文------>AES加密-->base64加密-->密文
 *
 *
 *解密方式:
 *  key->md5加密
 *          |
 *  密文------>base64解密-->AES解密-->明文
 */
class SymmetricCryptor {
    var options: CCOptions = 0            // 工作模式 Options (i.e: kCCOptionECBMode + kCCOptionPKCS7Padding)
    var iv: NSData?                       // 初始化向量
    
    //MARK: - 初始化时候定义工作模式
    init(options: Int) {
        self.options = CCOptions(options)
    }
    
    //MARK: - 传入明文和密钥，返回密文
    func crypt(string string: String, key: String) throws -> String {
        do {
            //md5加密key
            let key = key.md5
            //明文转NSData
            
            if let data = (string as NSString).dataUsingEncoding(NSUTF32StringEncoding) {
                //明文AES加密
                let AESCrypt = try self.cryptoOperation(data, key: key, operation: CCOperation(kCCEncrypt))
                //base64加密
                let base64String = AESCrypt.base64EncodedStringWithOptions(.Encoding64CharacterLineLength)
                return base64String
            } else {
                throw SymmetricCryptorError.WrongInputData
            }
        } catch {
            throw(error)
        }
    }
    
    //传入密文编码和密钥，返回明文
    func decrypt(string string: String, key: String) throws -> String  {
        do {
            //md5加密key
            let key = key.md5
            //base64解密
            if let base64Data = NSData(base64EncodedString: string, options: .IgnoreUnknownCharacters) {
                //AES解密
                let AESData = try self.cryptoOperation(base64Data, key: key, operation: CCOperation(kCCDecrypt))
                let decryptString = NSString(data: AESData, encoding: NSUTF32StringEncoding) as! String
                return decryptString
            }else {
                return "编码格式错误"
            }
        } catch {
            throw(error)
        }
    }
    
    /**
     *参数：
     *  inputData:      数据
     *  key:            密钥
     *  operation:      操作方式(kCCEncrypt/kCCDecrypt)
     */
    internal func cryptoOperation(inputData: NSData, key: String, operation: CCOperation) throws -> NSData {
        
        let keyData: NSData! = (key as NSString).dataUsingEncoding(NSUTF8StringEncoding)as NSData!
        let keyBytes         = UnsafePointer<Void>(keyData.bytes)
        let keyLength        = Int(kCCKeySizeAES256)
        let dataLength       = Int(inputData.length)
        let dataBytes        = UnsafePointer<Void>(inputData.bytes)
        let bufferData       = NSMutableData(length: Int(dataLength) + kCCBlockSizeAES128)!
        let bufferPointer    = UnsafeMutablePointer<Void>(bufferData.mutableBytes)
        let bufferLength     = Int(bufferData.length)
        let ivBuffer         = iv == nil ? nil : UnsafePointer<Void>(iv!.bytes)
        var bytesDecrypted   = Int(0)
        kCCOptionPKCS7Padding
        let cryptStatus = CCCrypt(
            operation,                          // 加密／解密
            CCAlgorithm(kCCAlgorithmAES128),    // 算法
            options,                            // 模式
            keyBytes,                           // 密钥子节数
            keyLength,                          // 密钥长度
            ivBuffer,                           // IV（初始化向量）
            dataBytes,                          // 数据子节数
            dataLength,                         // 数据长度
            bufferPointer,                      // output buffer
            bufferLength,                       // output buffer length
            &bytesDecrypted)                    // output bytes decrypted real length
        if Int32(cryptStatus) == Int32(kCCSuccess) {
            bufferData.length = bytesDecrypted // Adjust buffer size to real bytes
            print(bufferData)
            return bufferData as NSData
        } else {
            print("Error in crypto operation: \(cryptStatus)")
            throw(SymmetricCryptorError.CryptOperationFailed)
        }
    }
    
//    //MARK: - 获取本机UUID，进行md5加密
//    func getMD5(key: String) -> String{
//        //        let identifierNumber = UIDevice.currentDevice().identifierForVendor?.UUIDString
//        //        let md5Key = identifierNumber!.md5
//        return key.md5
//    }
}

//MARK: - MD5加密
extension String  {
    var md5: String! {
        let str = self.cStringUsingEncoding(NSUTF8StringEncoding)
        let strLen = CC_LONG(self.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        let digestLen = Int(CC_MD5_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        CC_MD5(str!, strLen, result)
        return stringFromBytes(result, length: digestLen)
    }
    
    func stringFromBytes(bytes: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String{
        let hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", bytes[i])
        }
        bytes.dealloc(length)
        return String(format: hash as String)
    }
}

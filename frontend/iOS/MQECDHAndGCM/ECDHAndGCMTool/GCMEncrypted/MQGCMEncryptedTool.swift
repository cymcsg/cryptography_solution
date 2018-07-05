//
//  MQGCMEncryptedTool.swift
//  MQECDHAndGCM
//
//  Created by mengJing on 2018/7/4.
//  Copyright © 2018年 mengJing. All rights reserved.
//

import Foundation
import CryptoSwift

/// MARK：gcm 加密/解密
public class MQGCMEncryptedTool : NSObject {
    
    public func gcmEncrypted(dataStr:String,shareKeyStr:String,nonceStr:String)->NSString {
        
        let key = Array<UInt8>(hex: shareKeyStr.sha256())
        let nonce = Array<UInt8>(hex: nonceStr)

        let plaintext:Array<UInt8> = dataStr.bytes
        
        print("key=\(key),keyStr=\(shareKeyStr)")
        print("nonce=\(nonce),nonceStr=\(nonceStr)")
        print("plaintext=\(plaintext),dataStr=\(dataStr)")
        
        
        let gcm = GCM(iv: nonce, mode: .combined) // detached
        let aes = try! AES(key: key, blockMode: gcm, padding: .noPadding)
        let encrypted = try! aes.encrypt(plaintext)
        
        print("GCM加密:\(encrypted.toHexString())")
        
        let result:NSString = gcmDecrypt(encryptedResult: encrypted,shareKeyStr:shareKeyStr,nonceStr:nonceStr,isJsonDict: false) as! NSString
        print("result:\(result)")
        
        return encrypted.toHexString() as NSString
    }

    /** gcm 加密 new */
    public func gcmEncrypted(dict:NSDictionary,shareKeyStr:String,nonceStr:String)->NSString {
        
        let jsonData:NSData = try! JSONSerialization.data(withJSONObject: dict, options: []) as NSData
        
        let jsonStr = String(data: jsonData as Data, encoding: String.Encoding.utf8) // ascii
        //        let jsonStringFromat:String = (JSONString?.replacingOccurrences(of: "\\/", with: "/"))!
        let jsonStringFromat:String = jsonStr!.replacingOccurrences(of: "\\/", with: "/", options: String.CompareOptions.caseInsensitive, range: nil)
        
        return gcmEncrypted(dataStr: jsonStringFromat, shareKeyStr: shareKeyStr, nonceStr: nonceStr)
    }
    
    /** gcm 解密 new */
    public func gcmDecrypt(encryptedResult:Array<UInt8>,shareKeyStr:String,nonceStr:String)->Any {
        let key = Array<UInt8>(hex: shareKeyStr.sha256())
        let nonce = Array<UInt8>(hex: nonceStr)
        let decGCM = GCM(iv: nonce, mode: .combined)
        let aes = try! AES(key: key, blockMode: decGCM, padding: .noPadding)
        let decrypted = try! aes.decrypt(encryptedResult)
        let jsonData:Data = Data(bytes: decrypted, count: decrypted.count)
        let encryptedResult = try! JSONSerialization.jsonObject(with: jsonData, options: [])
        print("GCM 解密 = \(encryptedResult)")
        return encryptedResult
    }
    
    /** gcm 解密 new */
    public func gcmDecrypt(encryptedResult:Array<UInt8>,shareKeyStr:String,nonceStr:String,isJsonDict:Bool)->Any {
        let key = Array<UInt8>(hex: shareKeyStr.sha256())
        let nonce = Array<UInt8>(hex: nonceStr)
        let decGCM = GCM(iv: nonce, mode: .combined)
        let aes = try! AES(key: key, blockMode: decGCM, padding: .noPadding)
        let decrypted = try! aes.decrypt(encryptedResult)
        let jsonData:Data = Data(bytes: decrypted, count: decrypted.count)
        
        if isJsonDict == true {
            let encryptedResult = try! JSONSerialization.jsonObject(with: jsonData, options: [])
            print("GCM 解密 = \(encryptedResult)")
            return encryptedResult
        }
        let encryptedResult:String = String(data: jsonData, encoding: String.Encoding.utf8) ?? ""
        print("GCM 解密 = \(encryptedResult)")
        return encryptedResult
    }
    
    /** gcm 解密 new */
    public func gcmDecrypt(encryptedStr:String,shareKeyStr:String,nonceStr:String,isJsonDict:Bool)->Any {
        let key = Array<UInt8>(hex: shareKeyStr.sha256())
        let nonce = Array<UInt8>(hex: nonceStr)
        let encrypted = Array<UInt8>(hex: encryptedStr)
        
        let decGCM = GCM(iv: nonce, mode: .combined)
        let aes = try! AES(key: key, blockMode: decGCM, padding: .noPadding)
        let decrypted = try! aes.decrypt(encrypted)
        let jsonData:Data = Data(bytes: decrypted, count: decrypted.count)
        
        if isJsonDict == true {
            let encryptedResult = try! JSONSerialization.jsonObject(with: jsonData, options: [])
            print("GCM 解密 = \(encryptedResult)")
            return encryptedResult
        }
        let encryptedResult:String = String(data: jsonData, encoding: String.Encoding.utf8) ?? ""
        print("GCM 解密 = \(encryptedResult)")
        return encryptedResult
    }
    
//    /** 密码随机盐加密 */
//    private func passwordFormat(dict:NSMutableDictionary,salt:String)->NSDictionary {
//        if dict["password"] != nil {
//            let password:String = dict["password"] as! String
//            dict["password"] = JFBCrypt.hashPassword(password, withSalt: salt)
//        }
//
//        if dict["old_password"] != nil {
//            let old_password:String = dict["old_password"] as! String
//            dict["old_password"] = JFBCrypt.hashPassword(old_password, withSalt: salt)
//        }
//
//        if dict["new_password"] != nil {
//            let new_password:String = dict["new_password"] as! String
//            dict["new_password"] = JFBCrypt.hashPassword(new_password, withSalt: salt)
//        }
//        return dict.copy() as! NSDictionary;
//    }
    
}

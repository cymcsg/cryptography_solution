//
//  MQECDHAndEncryptedTool.h
//  MQECDHAndGCM
//
//  Created by mengJing on 2018/7/4.
//  Copyright © 2018年 mengJing. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MQECDHTool.h"


// ShareKeyLengthType: 必须为 32 的倍数
typedef NS_ENUM(NSUInteger,ShareKeyLenType){
    ShareKeyLenTypeWith32 = 32,
    ShareKeyLenTypeWith64 = 64,
    ShareKeyLenTypeWith128 = 128,
};

// ShareKeyLengthType: 必须为 32 的倍数
typedef NS_ENUM(NSUInteger,ShareKeyLengthType){
    ShareKeyLengthTypeWith32 = 32,
    ShareKeyLengthTypeWith64 = 64,
    ShareKeyLengthTypeWith128 = 128,
};


@interface MQECDHAndEncryptedTool : NSObject

///** 私钥PEM: PublicKeyInitialTag + Base64(data) + PublicKeyFinalTag */
//@property (strong, nonatomic) NSString *privateKeyPEM;
//
///** 公钥PEM: PrivateKeyInitialTag + Base64(data) + PrivateKeyFinalTag */
//@property (strong, nonatomic) NSString *publicKeyPEM;
//
///** 公钥DER: Base64(data) */
//@property (strong, nonatomic) NSString *publicKeyDER;
///** 私钥DER: Base64(data) */
//@property (strong, nonatomic) NSString *privateKeyDER;

@property (strong, nonatomic) MQECDHKeyPairs *keyPairs;


/** shareKey: 16进制 */
@property (strong, nonatomic) NSString *shareKey;

@property (strong, nonatomic) NSString *encryptStr;
@property (strong, nonatomic) id decryptStr;

+ (instancetype)shareInstance;

/** create keyPair: 生成 ECC 的公钥、私钥 */
-(MQECDHKeyPairs *) createKeyPairs;

/** DER 格式输出: Base64(data) */
- (NSString *)base64StringDERFormat:(NSString *)pemFormatString;

/** DH(Diffie-Hellman)算法:生成ShareKey ( 自持私钥 + 三方公钥) */
- (NSString *)getShareKeyFromPrivatePem:(NSString *)privatePem PeerPubPem:(NSString *)peerPubPem shareKeyLen:(ShareKeyLengthType) sharekeyLength;
// shareKeyStr:String,nonceStr:String

/** GCM 加密字符串 */
-(NSString *) gcmEncryptedWithDataStr:(NSString *) dataStr shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr;

/** GCM 加密 dict */
-(NSString *) gcmEncryptedWithDict:(NSDictionary *) dict shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr;

/** GCM 解密 */
-(NSString *) gcmDecrypt:(NSArray<NSNumber *> *) encryptedResult shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr;

/** GCM 解密 */
-(NSString *) gcmDecryptWithEncryptStr:(NSString *) encryptedStr shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr;

@end

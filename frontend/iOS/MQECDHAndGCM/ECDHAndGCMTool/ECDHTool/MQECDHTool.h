//
//  MQECDHTool.h
//  MengOCToSwift
//
//  Created by mengJing on 2018/6/21.
//  Copyright © 2018年 mengJing. All rights reserved.
//

#import <Foundation/Foundation.h>

//// ShareKeyLengthType: 必须为 32 的倍数
//typedef NS_ENUM(NSUInteger,ShareKeyLengthType){
//    ShareKeyLengthTypeWith32 = 32,
//    ShareKeyLengthTypeWith64 = 64,
//    ShareKeyLengthTypeWith128 = 128,
//};

@interface MQECDHKeyPairs : NSObject

/** 私钥PEM: PublicKeyInitialTag + Base64(data) + PublicKeyFinalTag */
@property (strong, nonatomic) NSString *privateKeyPEM;

/** 公钥PEM: PrivateKeyInitialTag + Base64(data) + PrivateKeyFinalTag */
@property (strong, nonatomic) NSString *publicKeyPEM;

/** 公钥DER: Base64(data) */
@property (strong, nonatomic) NSString *publicKeyDER;
/** 私钥DER: Base64(data) */
@property (strong, nonatomic) NSString *privateKeyDER;

@end


@interface MQECDHTool : NSObject

@property (strong, nonatomic) MQECDHKeyPairs *keyPairs;


+ (instancetype)shareInstance;

/** create keyPair: 生成 ECC 的公钥、私钥 */
-(MQECDHKeyPairs *) createKeyPairs;

/** DER 格式输出: Base64(data) */
- (NSString *)base64StringDERFormat:(NSString *)pemFormatString;

/** DH(Diffie-Hellman)算法:生成ShareKey ( 自持私钥 + 三方公钥) */
- (NSString *)getShareKeyFromPrivatePem:(NSString *)privatePem PeerPubPem:(NSString *)peerPubPem shareKeyLen:(NSUInteger) sharekeyLength;

@end

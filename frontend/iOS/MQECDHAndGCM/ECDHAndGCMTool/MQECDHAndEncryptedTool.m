//
//  MQECDHAndEncryptedTool.m
//  MQECDHAndGCM
//
//  Created by mengJing on 2018/7/4.
//  Copyright © 2018年 mengJing. All rights reserved.
//

#import "MQECDHAndEncryptedTool.h"
#import "MQECDHAndGCM-Swift.h"

@interface MQECDHAndEncryptedTool()

@property (nonatomic, strong) MQECDHTool *ecdhTool;
@property (nonatomic, strong) MQGCMEncryptedTool *encryptedTool;
@end

@implementation MQECDHAndEncryptedTool

static MQECDHAndEncryptedTool* _instance;

+(instancetype)allocWithZone:(struct _NSZone *)zone {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _instance = [super allocWithZone:zone];
    });
    return _instance;
}

+ (instancetype)shareInstance {
    return [[self alloc] init];
}

/** 生成 ECC 的公钥、私钥 */
-(MQECDHKeyPairs *) createKeyPairs{
    
    self.ecdhTool = [MQECDHTool shareInstance];
    self.keyPairs = [self.ecdhTool createKeyPairs];
    
        
//        self.publicKeyPEM = self.ecdhTool.publicKeyPEM;
//        self.publicKeyDER = self.ecdhTool.publicKeyDER;
//        self.privateKeyPEM = self.ecdhTool.privateKeyPEM;
//        self.privateKeyDER = self.ecdhTool.privateKeyDER;
    
    return self.keyPairs;
}

/** DH(Diffie-Hellman)算法:生成ShareKey ( 自持私钥 + 三方公钥) */
- (NSString *)getShareKeyFromPrivatePem:(NSString *)privatePem PeerPubPem:(NSString *)peerPubPem shareKeyLen:(ShareKeyLengthType) sharekeyLength {
    
    if ((privatePem.length == 0) || (peerPubPem.length == 0)) {
        NSLog(@"自持私钥 或 三方公钥 不能为空!!");
        return @"";
    }
    
    self.shareKey = [self.ecdhTool getShareKeyFromPrivatePem:privatePem PeerPubPem:peerPubPem shareKeyLen:sharekeyLength];
    
    return self.shareKey;
}

/** DER 格式输出: Base64(data) */
- (NSString *)base64StringDERFormat:(NSString *)pemFormatString {
    return [self.ecdhTool base64StringDERFormat:pemFormatString];
}

/** GCM 加密字符串 */
-(NSString *) gcmEncryptedWithDataStr:(NSString *) dataStr shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr {
    self.encryptedTool = [[MQGCMEncryptedTool alloc] init];
    self.encryptStr = [self.encryptedTool gcmEncryptedWithDataStr:dataStr shareKeyStr:shareKeyStr nonceStr:nonceStr];
    return self.encryptStr;
}


/** GCM 加密 dict */
-(NSString *) gcmEncryptedWithDict:(NSDictionary *) dict shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr{
    
    self.encryptedTool = [[MQGCMEncryptedTool alloc] init];
    self.encryptStr = [self.encryptedTool gcmEncryptedWithDict:dict shareKeyStr:shareKeyStr nonceStr:nonceStr];
    return self.encryptStr;
}

/** GCM 解密 */
-(NSDictionary *) gcmDecrypt:(NSArray<NSNumber *> *) encryptedResult shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr {
    
    self.encryptedTool = [[MQGCMEncryptedTool alloc] init];
    self.decryptStr = [self.encryptedTool gcmDecryptWithEncryptedResult:encryptedResult shareKeyStr:shareKeyStr nonceStr:nonceStr];
    return self.decryptStr;
}

/** GCM 解密 */
-(NSString *) gcmDecryptWithEncryptStr:(NSString *) encryptedStr shareKeyStr:(NSString *) shareKeyStr nonceStr:(NSString *) nonceStr {
    self.encryptedTool = [[MQGCMEncryptedTool alloc] init];
    self.decryptStr = [self.encryptedTool gcmDecryptWithEncryptedStr:encryptedStr shareKeyStr:shareKeyStr nonceStr:nonceStr isJsonDict:NO];
    return self.decryptStr;
}

@end

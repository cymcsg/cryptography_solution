//
//  MQECDHTool.m
//  MengOCToSwift
//
//  Created by mengJing on 2018/6/21.
//  Copyright © 2018年 mengJing. All rights reserved.
//

#import "MQECDHTool.h"
#import <openssl/ssl.h>

#define kShareKeyLen 32
#define kCurveName NID_secp384r1 // NID_secp256k1

@implementation MQECDHKeyPairs

@end

@implementation MQECDHTool

static MQECDHTool* _instance;

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
-(MQECDHKeyPairs *) createKeyPairs {
    
    int asn1Flag = OPENSSL_EC_NAMED_CURVE;
    int form = POINT_CONVERSION_UNCOMPRESSED;
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    eckey = EC_KEY_new();
    group = EC_GROUP_new_by_curve_name(kCurveName);
    EC_GROUP_set_asn1_flag(group, asn1Flag);
    EC_GROUP_set_point_conversion_form(group, form);
    EC_KEY_set_group(eckey, group);
    
    int resultFromKeyGen = EC_KEY_generate_key(eckey);
    if (resultFromKeyGen != 1){
        raise(-1);
    }
    self.keyPairs = [[MQECDHKeyPairs alloc] init];
    self.keyPairs.publicKeyPEM = [self getPemFormatWithECKey:eckey isPublicType:YES];
    self.keyPairs.privateKeyPEM = [self getPemFormatWithECKey:eckey isPublicType:NO];
    self.keyPairs.publicKeyDER = [self base64StringDERFormat:self.keyPairs.publicKeyPEM];
    self.keyPairs.privateKeyDER = [self base64StringDERFormat:self.keyPairs.privateKeyPEM];
    
    EC_KEY_free(eckey);
    return self.keyPairs;
}

/** DH(Diffie-Hellman)算法:生成ShareKey ( 自持私钥 + 三方公钥) */
- (NSString *)getShareKeyFromPrivatePem:(NSString *)privatePem PeerPubPem:(NSString *)peerPubPem shareKeyLen:(NSUInteger) sharekeyLength {
    
    if ((privatePem.length == 0) || (peerPubPem.length == 0)) {
        NSLog(@"自持私钥 或 三方公钥 不能为空!!");
        return @"";
    }
    
    // 根据私钥PEM字符串,生成私钥
    EC_KEY *clientEcKey = [self ecKeyFromPEM:privatePem isPublicType:NO];
    
    if ((sharekeyLength != 32) || (sharekeyLength != 64)) {
//    if (sharekeyLength == 0) {
        // 获取私钥长度
        const EC_GROUP *group = EC_KEY_get0_group(clientEcKey);
        sharekeyLength = (EC_GROUP_get_degree(group) + 7)/8;
    }
    
    // 根据peerPubPem生成新的公钥EC_KEY
    EC_KEY *serverEcKey = [self ecKeyFromPEM:peerPubPem isPublicType:YES];
    if (serverEcKey == NULL) {
        NSLog(@"新的公钥 = NULL");
        return @"";
    }
    const EC_POINT *serverEcKeyPoint = EC_KEY_get0_public_key(serverEcKey);
    char shareKey[sharekeyLength];
    ECDH_compute_key(shareKey, sharekeyLength, serverEcKeyPoint, clientEcKey,  NULL);
    // 释放公钥,释放私钥
    EC_KEY_free(clientEcKey);
    EC_KEY_free(serverEcKey);
    
    NSData *shareKeyData = [NSData dataWithBytes:shareKey length:sharekeyLength];
    
    NSString *shareKeyStr = [shareKeyData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    return shareKeyStr;
}

/** 将PEM格式的公钥字符串转化成EC_KEY */
-(EC_KEY *) ecKeyFromPEM:(NSString *) pemKeyString isPublicType:(BOOL)isPublicType{
    
    const char *buffer = [pemKeyString UTF8String];
    BIO *bpubkey = BIO_new_mem_buf(buffer, (int)strlen(buffer));
    
    if (isPublicType == YES) {
        // 输出 publicKey 的 EC_KEY
        EVP_PKEY *publicPem = PEM_read_bio_PUBKEY(bpubkey, NULL, NULL, NULL);
        if (publicPem == NULL) {
            NSLog(@"publickey from PEM error");
            return (EC_KEY *)NULL;
        }
        EC_KEY *ec_cdata = EVP_PKEY_get1_EC_KEY(publicPem);
        BIO_free_all(bpubkey);
        return ec_cdata;
    }else{
        // 输出 pricateKey 的 EC_KEY
        EC_KEY *pricateKey = PEM_read_bio_ECPrivateKey(bpubkey, NULL, NULL, NULL);
        if (pricateKey == NULL) {
            NSLog(@"pricateKey from PEM error");
            return (EC_KEY *)NULL;
        }
        BIO_free_all(bpubkey);
        return pricateKey;
    }
}

/** PEM 格式输出:PublicKeyInitialTag + Base64(data) + PublicKeyFinalTag */
- (NSString *)getPemFormatWithECKey:(EC_KEY *)ecKey isPublicType:(BOOL)isPublicType{
    if (ecKey == nil) {
        return nil;
    }
    BUF_MEM *buf;
    buf = BUF_MEM_new();
    BIO *bio = BIO_new(BIO_s_mem());
    if (isPublicType == YES) {
        PEM_write_bio_EC_PUBKEY(bio, ecKey);
    }else{
        PEM_write_bio_ECPrivateKey(bio, ecKey, NULL, NULL, 0, NULL, NULL);
    }
    BIO_get_mem_ptr(bio, &buf);
    
//    NSString *pemString = [NSString stringWithFormat:@"%s",buf->data];
    NSString *pemString = [[NSString alloc] initWithBytes:buf->data length:(NSUInteger)buf->length encoding:NSASCIIStringEncoding];
    
    BIO_free(bio);
    return pemString;
}

/** DER 格式输出: Base64(data) */
- (NSString *)base64StringDERFormat:(NSString *)pemFormatString {
    return [[pemFormatString componentsSeparatedByString:@"-----"] objectAtIndex:2];
}


@end

//
//  ViewController.m
//  MQECDHAndGCM
//
//  Created by mengJing on 2018/7/2.
//  Copyright © 2018年 mengJing. All rights reserved.
//

#import "ViewController.h"
#import "MQECDHAndEncryptedTool.h"

@interface ViewController ()

@end

@implementation ViewController

-(void) ecdhEncrypted {
    MQECDHAndEncryptedTool * encryptedTool = [MQECDHAndEncryptedTool shareInstance];
    MQECDHKeyPairs *keyPairs = [encryptedTool createKeyPairs];
//    NSLog(@"pub=%@",keyPairs.publicKeyDER);
    
    NSString *pub = @"-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE57afGUeENdd9KGR9s7HTrW2fyR7vd1XE9t+fYj2A8whuk9OetMIQg4+4FIsSK0KwKzaQYg3hqjU8kGJi29KUgDZxZrYR+PDAJRSFzWzBcHxaH4tjhBKZc6eNLBtiDXzX\n-----END PUBLIC KEY-----";
    NSString *shareKey = [encryptedTool getShareKeyFromPrivatePem:keyPairs.privateKeyPEM PeerPubPem:pub shareKeyLen:ShareKeyLengthTypeWith32];
//    NSLog(@"str=%@",shareKey);
    
    NSString *shareKey2=@"YKVD42i3sY17MIfV8BERh0oM7Ti2AcDkLH+4gG/RVHaUKsD5EhOXs5ugTGKNXS3j";
    NSString *nonce = @"540929e21c04a3a4bef16fe3";
    
    // 63d28a6da98fa65dafae3fc4129864ee70f821eecfda079e9112ae05
    // [99, 210, 138, 109, 169, 143, 166, 93, 175, 174, 63, 196, 18, 152, 100, 238, 112, 248, 33, 238, 207, 218, 7, 158, 145, 18, 174, 5]
    
    NSString *encrypt = [encryptedTool gcmEncryptedWithDataStr:@"张三你好" shareKeyStr:shareKey2 nonceStr:nonce];
    
    // GCM加密:63d28a6da98fa65dafae3fc4129864ee70f821eecfda079e9112ae05
    
    NSLog(@"加密结果=%@",encrypt);
    
    
    id decrypt = [encryptedTool gcmDecryptWithEncryptStr:encrypt shareKeyStr:shareKey2 nonceStr:nonce];
    NSLog(@"解密结果=%@",decrypt);

//    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE57afGUeENdd9KGR9s7HTrW2fyR7vd1XE
//    9t+fYj2A8whuk9OetMIQg4+4FIsSK0KwKzaQYg3hqjU8kGJi29KUgDZxZrYR+PDA
//    JRSFzWzBcHxaH4tjhBKZc6eNLBtiDXzX
//    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOFKGFN/jXM03SgOHIn5uL/b/UONIEKXU
//    gSe889Zaf3uoaC2NgC3tKC1SgwLh3fO1PSb3NniIRD0eq9Dk63C3EajkeorM1xHu
//    wb2X+FfpPUcQa0jsNNduyDdcCMHoE57f

    
    
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self ecdhEncrypted];
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end

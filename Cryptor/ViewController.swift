//
//  ViewController.swift
//  Cryptor
//
//  Created by mac on 16/7/19.
//  Copyright © 2016年 mac. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var cypherTextView: UITextView!
    @IBOutlet weak var decypherTextView: UITextView!
    @IBOutlet weak var symmetricKeyLabel: UITextField!
    
    var cypherText = ""                                     //明文字符串
    var decypherText = ""                                   //密文字符串
    var cypherData: NSData?                                  //加密／解密的编码
    var iv: NSData?                                          //初始化向量
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    //MARK: -加密
    @IBAction func cypher(sender: UIButton) {
        //对密钥md5加密
        let md5Key = symmetricKeyLabel.text!
        
        //获取明文，为空时，弹出警告
        if cypherTextView.text?.characters.count < 1 {
            showAlertWithMessage("请填写明文")
            return
        }else {
            cypherText = cypherTextView.text!
        }
        let cypher = SymmetricCryptor(options: kCCOptionPKCS7Padding)
        do {
            //获取密文
            decypherText = try cypher.crypt(string: cypherText, key: md5Key)
            decypherTextView.text = "[ekanet.cn]" + decypherText //as String
            cypherTextView.text = ""
        } catch {
            self.showAlertWithMessage("明文无法加密")
        }
    }

    //MARK: -解密
    @IBAction func decypher(sender: UIButton) {
        //对密钥md5加密
        let md5Key = symmetricKeyLabel.text!

        //获取密文，为空时，弹出警告
        if decypherTextView.text?.characters.count < 1 {
            showAlertWithMessage("密文为空！")
            return
        }else {
            decypherText = decypherTextView.text!
        }
        
        //判断密文前缀是否正确
        if decypherText.hasPrefix("[ekanet.cn]") {
            //截取前缀
            decypherText =  decypherText.substringFromIndex(decypherText.startIndex.advancedBy(11))
        }else {
            showAlertWithMessage("密文格式不正确")
            return
        }
        let cypher = SymmetricCryptor(options: kCCOptionPKCS7Padding)
        do {
            //获取密文编码
            cypherText = try cypher.decrypt(string: decypherText, key: md5Key)
            if cypherText == "编码格式错误" {
                self.showAlertWithMessage("编码格式错误")
                return
            }
            cypherTextView.text = cypherText
            decypherText = ""
            decypherTextView.text = ""
        } catch {
            self.showAlertWithMessage("密文无法解密，错误： \(error)")
        }
    }
    
    // MARK: - 弹框
    func showAlertWithMessage(msg: String, completion: (() -> Void)? = nil) {
        let alert = UIAlertController(title: nil, message: msg, preferredStyle: .Alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .Default, handler: nil))
        self.presentViewController(alert, animated: true, completion: completion)
    }
    
    //MARK: - 点击空白处收缩键盘
    override func touchesBegan(touches: Set<UITouch>, withEvent event: UIEvent?) {
        self.view.endEditing(true)
    }
}
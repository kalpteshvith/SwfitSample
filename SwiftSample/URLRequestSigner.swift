//
//  kpNewServerClassViewController.swift
//  BreathingApp
//
//  Created by Kalpesh Panchasara on 26/08/20.
//  Copyright © 2020 Ashwin. All rights reserved.
//

import UIKit
import Foundation
import CommonCrypto
import CryptoKit
import CryptoTokenKit

class URLRequestSigner: NSObject
{

        private let hmacShaTypeString = "AWS4-HMAC-SHA256"
        private let awsRegion = "us-east-1"
        private let serviceType = "execute-api"
        private let aws4Request = "aws4_request"
        
        private let iso8601Formatter: DateFormatter = {
            let formatter = DateFormatter()
            formatter.calendar = Calendar(identifier: .iso8601)
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.dateFormat = "yyyyMMdd'T'HHmmssXXXXX"
            return formatter
        }()
        
        private func iso8601() -> (full: String, short: String) {
            let date = iso8601Formatter.string(from: Date())
            let index = date.index(date.startIndex, offsetBy: 8)
            let shortDate = date.substring(to: index)
            return (full: date, short: shortDate)
        }
        
        
        func sign(request: URLRequest, secretSigningKey: String, accessKeyId: String) -> URLRequest? {
            var signedRequest = request
            let date = iso8601()
            
            guard let bodyData = signedRequest.httpBody, let body = String(data: bodyData, encoding: .utf8), let url = signedRequest.url, let host = url.host
                else { return .none }

            signedRequest.addValue(host, forHTTPHeaderField: "Host")
            signedRequest.addValue(date.full, forHTTPHeaderField: "X-Amz-Date")
            
            guard let headers = signedRequest.allHTTPHeaderFields, let method = signedRequest.httpMethod
                else { return .none }
            
            let signedHeaders = headers.map{ $0.key.lowercased() }.sorted().joined(separator: ";")
            
            let canonicalRequestHash = [
                method,
                url.path,
                url.query ?? "",
                headers.map{ $0.key.lowercased() + ":" + $0.value }.sorted().joined(separator: "\n"),
                "",
                signedHeaders,
                body.sha256()
            ].joined(separator: "\n").sha256()
            
            let credential = [date.short, awsRegion, serviceType, aws4Request].joined(separator: "/")
            
            let stringToSign = [
                hmacShaTypeString,
                date.full,
                credential,
                canonicalRequestHash
                ].joined(separator: "\n")
            
            guard let signature = hmacStringToSign(stringToSign: stringToSign, secretSigningKey: secretSigningKey, shortDateString: date.short)
                else { return .none }
            
            let authorization = hmacShaTypeString + " Credential=" + accessKeyId + "/" + credential + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
            signedRequest.addValue(authorization, forHTTPHeaderField: "Authorization")
            
            return signedRequest
        }
        
        private func hmacStringToSign(stringToSign: String, secretSigningKey: String, shortDateString: String) -> String?
        {
            let secret = NSString(format: "AWS4%@", secretSigningKey).data(using: String.Encoding.utf8.rawValue)!
            let date = hmac(string: (shortDateString as NSString).substring(to: 8) as NSString, key: secret as NSData)
            let region = hmac(string: awsRegion as NSString, key: date)
            let service = hmac(string: serviceType as NSString, key: region)
            let credentials = hmac(string: "aws4_request", key: service)
            let sig = hmac(string: stringToSign as NSString, key: credentials)
            return hexdigest(data: sig)
            /*let k1 : String = "AWS4" + secretSigningKey
            if #available(iOS 13.0, *) {
                guard let sk1 = try? HMAC(key: (k1.utf8), variant: .sha256).authenticate([UInt8](shortDateString.utf8)),
                    let sk2 = try? HMAC(key: sk1, variant: .sha256).authenticate([UInt8](awsRegion.utf8)),
                    let sk3 = try? HMAC(key: sk2, variant: .sha256).authenticate([UInt8](serviceType.utf8)),
                    let sk4 = try? HMAC(key: sk3, variant: .sha256).authenticate([UInt8](aws4Request.utf8)),
                    let signature = try? HMAC(key: sk4, variant: .sha256).authenticate([UInt8](stringToSign.utf8)) else { return .none }
            } else {
                // Fallback on earlier versions
            }
            
            return signature.toHexString()*/
        }
          private func hexdigest(data: NSData) -> String {
            var hex = String()
        //    let bytes =  UnsafePointer<CUnsignedChar>(data.bytes)
            let bytes = data.bytes.assumingMemoryBound(to: UInt8.self)

            for i in 0...data.length - 1
            {
                hex += String(format: "%02x", bytes[i])
            }
        //    for (var i: Int=0; i<data.length; ++i) {
        //      hex += String(format: "%02x", bytes[i])
        //    }
            return hex
          }

      private func hmac(string: NSString, key: NSData) -> NSData
      {
    //    let keyBytes = UnsafePointer<CUnsignedChar>(key.bytes)
    //    let keyBytes = UnsafePointer<CUnsignedChar>(key.bytes)
        let keyBytes = key.bytes.assumingMemoryBound(to: UInt8.self)

        let data = string.cString(using: String.Encoding.utf8.rawValue)
        let dataLen = Int(string.lengthOfBytes(using: String.Encoding.utf8.rawValue))
        let digestLen = Int(CC_SHA256_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, key.length, data, dataLen, result);
        return NSData(bytes: result, length: digestLen)
      }



}
extension String {

    func sha256() -> String{
        if let stringData = self.data(using: String.Encoding.utf8) {
            return hexStringFromData(input: digest(input: stringData as NSData))
        }
        return ""
    }

    private func digest(input : NSData) -> NSData {
        let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        var hash = [UInt8](repeating: 0, count: digestLength)
        CC_SHA256(input.bytes, UInt32(input.length), &hash)
        return NSData(bytes: hash, length: digestLength)
    }

    private  func hexStringFromData(input: NSData) -> String {
        var bytes = [UInt8](repeating: 0, count: input.length)
        input.getBytes(&bytes, length: input.length)
        var hexString = ""
        for byte in bytes {
            hexString += String(format:"%02x", UInt8(byte))
        }
        return hexString
    }
}

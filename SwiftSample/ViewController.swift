//
//  ViewController.swift
//  SwiftSample
//
//  Created by Kalpesh Panchasara on 26/08/20.
//  Copyright © 2020 Kalpesh Panchasara. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad()
    {
        self.view.backgroundColor = UIColor.white
        
        let graphqlUrl = "https://hiw-stylus-mobile-sensor-uploads.nyc3.digitaloceanspaces.com/20200505-1588817811-789101112.json"
        let secretAccessKey = "d5bn7ih0rJUbange7Kx0B5jXWiVdYJPHpYLxV384IG0"
        let accessKeyId = "YEQNNHPDTCAWU4TDN2KP"
        let parameters = self.getStaticSensorData()
        
        let sessionConfig = URLSessionConfiguration.default
        
        let session = URLSession(configuration: sessionConfig, delegate: nil, delegateQueue: nil)
        
        guard let URL = URL(string: graphqlUrl) else { return }
        var request = URLRequest(url: URL)
        request.httpMethod = "PUT"
        
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
//        request.addValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "X-Amz-Content-Sha256")

        request.httpBody = parameters.data(using: String.Encoding.utf8)
        
                    guard let signedRequest = URLRequestSigner().sign(request: request, secretSigningKey: secretAccessKey, accessKeyId: accessKeyId) else { return }
                    let task = session.dataTask(with: signedRequest, completionHandler: { (data: Data?, response: URLResponse?, error: Error?) -> Void in
                        if let d = data, let _ = try? JSONSerialization.jsonObject(with: d, options: []) as? [String:AnyObject]
                        {
                            print("Success",response as Any)
                        }
                        else
                        {
                            print("Error",response as Any)
                        }
                    })
        task.resume()
        session.finishTasksAndInvalidate()

        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    func getStaticSensorData()->String
    {
        let parameters = "{\n  \"user_id\": 1939392394,\n  \"hiw_app_version\": \"v0.1.0\",\n  \"hiw_stylus\": {\n    \"uuid\": \"ba7c0e6f-c01c-4d12-a846-a7010a0f489b\",\n    \"firmware_version\": \"v0.1.0\",\n    \"battery_life\": \"83\",\n    \"bluetooth_address\": \"f0:fc:39:d1:d3:4d\"\n  },\n  \"user_device\": {\n    \"type\": \"mobile\",\n    \"carrier\": \"verizon\",\n    \"os\": \"android\",\n    \"os_version\": 10,\n    \"gmt_offset\": \"GMT-5:00\",\n    \"locale\": \"en\",\n    \"hardware\": {\n      \"manufacturer\": \"samsung\",\n      \"model\": \"galaxy-s8\",\n      \"imei\": \"392920488401742\",\n      \"meid\": null\n    }\n  },\n  \"data\": {\n    \"force_sensor_01\": {\n      \"collection_start_dt_local\": \"16-06-2020 17:42:28.126\", \n      \"collection_end_dt_local\": \"16-06-2020 17:42:58.126\",\n      \"collection_interval_ms\": 500,\n      \"collection_count\": 60,\n      \"readings_ohms\": [\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0\n        ]\n      },\n    \"force_sensor_02\": {\n      \"collection_start_dt_local\": \"16-06-2020 17:42:28.126\", \n      \"collection_end_dt_local\": \"16-06-2020 17:42:58.126\",\n      \"collection_interval_ms\": 500,\n      \"collection_count\": 60,\n      \"readings_ohms\": [\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0\n        ]\n      },\n    \"force_sensor_03\": {\n      \"collection_start_dt_local\": \"16-06-2020 17:42:28.126\", \n      \"collection_end_dt_local\": \"16-06-2020 17:42:58.126\",\n      \"collection_interval_ms\": 500,\n      \"collection_count\": 60,\n      \"readings_ohms\": [\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0\n        ]\n      },\n    \"force_sensor_04\": {\n      \"collection_start_dt_local\": \"16-06-2020 17:42:28.126\", \n      \"collection_end_dt_local\": \"16-06-2020 17:42:58.126\",\n      \"collection_interval_ms\": 500,\n      \"collection_count\": 60,\n      \"readings_ohms\": [\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0,\n        576,\n        576,\n        573,\n        526,\n        546,\n        424,\n        311,\n        118,\n        85,\n        0\n        ]\n      },\n    \"accelorometer_sensor_01\": {\n      \"collection_start_dt_local\": \"16-06-2020 17:42:28.126\", \n      \"collection_end_dt_local\": \"16-06-2020 17:42:58.126\",\n      \"collection_interval_ms\": 500,\n      \"collection_count\": 60,\n      \"readings_g\": [\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"0.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"1.0\",\n          \"z\": \"0.5\"\n        },\n        {\n          \"x\": \"0.5\",\n          \"y\": \"0.5\",\n          \"z\": \"1.0\"\n        }\n        ]\n      }\n }\n}"
        
        return parameters
    }

}

/* From Postman
 (lldb) NSDictionary *headers = @{
 @"X-Amz-Content-Sha256": @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
 @"X-Amz-Date": @"20200826T075308Z",
 @"Authorization": @"AWS4-HMAC-SHA256 Credential=YEQNNHPDTCAWU4TDN2KP/20200826/nyc3/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-hiw-mbl-os;x-amz-meta-hiw-mbl-uid;x-amz-meta-hiw-mbl-vr;x-amz-meta-hiw-styl-hw-id;x-amz-meta-hiw-styl-snsr-col-end-tmstmp;x-amz-meta-hiw-styl-snsr-col-strt-tmstmp, Signature=01d89e900633a2b8e9297e6507040f59d55d0ca32f40ce5e8c750b87dae59121"

 */

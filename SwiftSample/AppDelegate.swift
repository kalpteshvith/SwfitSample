//
//  AppDelegate.swift
//  SwiftSample
//
//  Created by Kalpesh Panchasara on 26/08/20.
//  Copyright © 2020 Kalpesh Panchasara. All rights reserved.
//

import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let view1 : ViewController = ViewController()
        let frame = UIScreen.main.bounds
        window = UIWindow(frame: frame)
        if let window = self.window
        {
            window.rootViewController = UINavigationController(rootViewController: view1)
        }
        window!.makeKeyAndVisible()
        // Override point for customization after application launch.
        return true
    }



}


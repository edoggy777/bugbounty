Mobile Platform Broadcast Testing Reference

This document contains broadcast intents and commands for testing mobile apps’ handling of system broadcasts, referrer data, cloud messaging, and more.  
**Warning:** Use these commands **only** on apps you own or have explicit permission to test. Never use real sensitive data; always follow responsible disclosure and security policies.

Install Referrer Testing
Tests how apps handle app store referrer data when installed.


Basic install referrer test
adb shell am broadcast -a com.platform.store.INSTALL_REFERRER \
  -n com.example.app/com.attribution.SingleInstallBroadcastReceiver \
  --es "referrer" "utm_source=test&utm_campaign=legitimate"

Multiple install referrer receiver test
adb shell am broadcast -a com.platform.store.INSTALL_REFERRER \
  -n com.example.app/com.attribution.MultipleInstallBroadcastReceiver \
  --es "referrer" "utm_source=test&utm_medium=test"
```

Package Update Notifications
Tests how apps respond to package replacement events.

Package replaced broadcast
adb shell am broadcast -a system.intent.action.MY_PACKAGE_REPLACED \
  -n com.example.app/com.example.app.UpdateNotificationReceiver

Package installed broadcast
adb shell am broadcast -a system.intent.action.PACKAGE_REPLACED \
  -d package:com.example.app
```

Cloud Messaging Testing
Tests cloud messaging and push notification handling.

Basic cloud message test
adb shell am broadcast -a com.platform.messaging.intent.RECEIVE \
  -n com.example.app/com.platform.cloudmsg.CloudMessagingReceiver \
  --es "platform.message_id" "test123"

Cloud messaging registration test
adb shell am broadcast -a com.platform.messaging.intent.REGISTRATION \
  -n com.example.app/com.platform.cloudmsg.CloudMessagingReceiver \
  --es "registration_id" "test_token"

Notification dismiss test
adb shell am broadcast -a com.platform.cloudmsg.NOTIFICATION_DISMISS \
  -n com.example.app/com.platform.cloudmsg.CloudMessagingReceiver


Locale and System State Changes
Tests how apps handle system configuration changes.

Locale change test
adb shell am broadcast -a system.intent.action.LOCALE_CHANGED \
  -n com.example.app/.LanguageReceiver \
  --es "system.intent.extra.LOCALE" "en_US"

Boot completed test
adb shell am broadcast -a system.intent.action.BOOT_COMPLETED \
  -n com.example.app/.BootReceiver

User present test
adb shell am broadcast -a system.intent.action.USER_PRESENT \
  -n com.example.app/.UserReceiver
```

Profile Installation Testing
Tests profile installer functionality for app optimization.

Basic profile install test
adb shell am broadcast -a com.platform.profileinstaller.action.INSTALL_PROFILE \
  -n com.example.app/com.platform.profileinstaller.ProfileInstallReceiver

Profile benchmark test
adb shell am broadcast -a com.platform.profileinstaller.action.BENCHMARK_OPERATION \
  -n com.example.app/com.platform.profileinstaller.ProfileInstallReceiver

Profile save test
adb shell am broadcast -a com.platform.profileinstaller.action.SAVE_PROFILE \
  -n com.example.app/com.platform.profileinstaller.ProfileInstallReceiver
```

Enterprise Security Testing
Tests enterprise security features (requires enterprise-enabled device).


Enterprise status check
adb shell am broadcast -a com.platform.enterprise.action.CHECK_STATUS

Secure container lock test
adb shell am broadcast -a "com.platform.enterprise.container.LOCK_SECUREFOLDER"

Enterprise license activation test
adb shell am broadcast -a "com.platform.enterprise.intent.action.LICENSE_ACTIVATE_DIALOG_INTERNAL"
```

Work Manager Diagnostics
Tests work manager diagnostic functionality.


Work diagnostics request
adb shell am broadcast -a com.platform.work.diagnostics.REQUEST_DIAGNOSTICS \
  -n com.example.app/com.platform.work.impl.diagnostics.DiagnosticsReceiver


Geofence and Location Testing
Tests location-based broadcast receivers.


Geofence event test
adb shell am broadcast -a com.locationservice.GEOFENCE_EVENT \
  -n com.example.app/com.locationservice.sdk.notify.geofence.GeofenceBroadcastReceiver
```

General Testing Tips

Using Broadcast Flags

Include stopped packages
adb shell am broadcast -a [ACTION] --include-stopped-packages

Run in foreground
adb shell am broadcast -a [ACTION] --receiver-foreground

Target specific package
adb shell am broadcast -p com.example.app -a [ACTION]


Monitoring Broadcasts

View broadcast logs
adb logcat | grep -E "broadcast|ActivityManager"

View specific app logs
adb logcat | grep com.example.app
```

Data Types for Testing

String extra
--es "key" "value"

Integer extra
--ei "key" 123

Boolean extra
--ez "key" true

Long extra
--el "key" 1234567890

URI data
-d "https://example.com"
```

Security Considerations

When testing broadcasts:
- Only test on apps you own or have permission to test
- Use test data, never real sensitive information
- Test in isolated environments
- Follow responsible disclosure for any issues found
- Ensure compliance with relevant security policies

Common Broadcast Actions

- `system.intent.action.BOOT_COMPLETED` - Device finished booting
- `system.intent.action.LOCALE_CHANGED` - System locale changed
- `system.intent.action.PACKAGE_REPLACED` - App package updated
- `com.platform.store.INSTALL_REFERRER` - App install attribution
- `com.platform.messaging.intent.RECEIVE` - Cloud message received
- `com.platform.profileinstaller.action.INSTALL_PROFILE` - Profile optimization

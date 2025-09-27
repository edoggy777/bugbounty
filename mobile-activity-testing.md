Mobile Activity Testing Reference

Deep Link Handler Testing
Tests how apps handle custom URL schemes and deep links. This helps identify improper URL validation and potential redirect vulnerabilities.

Basic deep link testing
adb shell am start -a system.intent.action.VIEW \
  -d "appscheme://test" \
  -n com.example.app/.ui.activity.MainActivity

Deep link with parameters
adb shell am start -a system.intent.action.VIEW \
  -d "appscheme://open?page=home" \
  -n com.example.app/.ui.activity.MainActivity

Deep link with redirect parameter testing
adb shell am start -a system.intent.action.VIEW \
  -d "appscheme://redirect?url=https://example.com" \
  -n com.example.app/.ui.activity.MainActivity

Multiple encoding levels testing
adb shell am start -a system.intent.action.VIEW \
  -d "https://example.com" \
  -n com.example.app/.ui.activity.MainActivity

adb shell am start -a system.intent.action.VIEW \
  -d "https%3A%2F%2Fexample.com" \
  -n com.example.app/.ui.activity.MainActivity

Payment Activity Testing
Tests payment flow activities for proper input validation and authorization. This identifies potential payment bypass or amount manipulation vulnerabilities.

Payment initiation testing
adb shell am start \
  -n com.example.app/com.example.payments.WebViewActivity \
  -d "dispatcher://checkout-initiate-payment-web-view?amount=1.00"

Payment chrome tab testing
adb shell am start \
  -n com.example.app/com.example.payments.ChromeTabActivity \
  -d "dispatcher://checkout-initiate-payment-chrome-tab?payment_url=https://example.com"

Payment with custom parameters
adb shell am start \
  -n com.example.app/.payments.PaymentActivity \
  --es "amount" "10.00" \
  --es "currency" "USD"

Main Activity Testing
Tests primary app entry points with various intents and data. This helps identify how apps handle unexpected input and external navigation.

Basic main activity launch
adb shell am start \
  -n com.example.app/.ui.MainActivity

Main activity with VIEW action
adb shell am start \
  -a system.intent.action.VIEW \
  -n com.example.app/.ui.MainActivity

Main activity with external URL
adb shell am start \
  -a system.intent.action.VIEW \
  -d "https://example.com" \
  -n com.example.app/.ui.MainActivity

Main activity with category
adb shell am start \
  -a system.intent.action.VIEW \
  -c system.intent.category.DEFAULT \
  -d "https://example.com" \
  -n com.example.app/.ui.MainActivity
```

Intro/Onboarding Activity Testing
Tests app introduction and setup flows. This identifies potential bypass mechanisms for onboarding security checks.

Basic intro activity
adb shell am start \
  -n com.example.app/.ui.activity.IntroActivity

Intro with deep link
adb shell am start \
  -d "appscheme://intro" \
  -n com.example.app/.ui.activity.IntroActivity

Intro with URL parameter
adb shell am start \
  -n com.example.app/.ui.activity.IntroActivity \
  --es "url" "https://example.com"

Intro with redirect testing
adb shell am start \
  -n com.example.app/.ui.activity.IntroActivity \
  -d "appscheme://redirect?url=https://example.com"

Financial/Trading Activity Testing
Tests financial app activities for proper validation and authorization. This helps identify potential trading manipulation or unauthorized transaction vulnerabilities.

Trading activity with parameters
adb shell am start \
  -n com.example.app/.trading.EarnActivity \
  --es "product_id" "TEST123" \
  --es "investment_amount" "100.00"

Trading activity with multiple parameters
adb shell am start \
  -n com.example.app/.trading.EarnActivity \
  --es "coin_type" "BTC" \
  --es "amount" "50.00" \
  --es "referral_code" "REF123"

Age Verification Testing
Tests age verification bypasses in apps with age-restricted content. This identifies potential unauthorized access to restricted features.

Age verification activity
adb shell am start \
  -n com.example.app/com.example.verification.AgeVerificationActivity \
  --ez "age_verified" true

Age verification with extra parameters
adb shell am start \
  -n com.example.app/com.example.verification.AgeVerificationActivity \
  --ei "age" 21 \
  --ez "verified" true

Web View Activity Testing
Tests embedded web view activities for proper URL validation. This identifies potential web view hijacking and URL redirection vulnerabilities.

Web view with URL
adb shell am start \
  -n com.example.app/.webview.WebViewActivity \
  -d "https://example.com"

Web view with intent data
adb shell am start \
  -a system.intent.action.VIEW \
  -n com.example.app/.webview.WebViewActivity \
  -d "https://example.com"

Web view with custom parameters
adb shell am start \
  -n com.example.app/.webview.WebViewActivity \
  --es "load_url" "https://example.com"

Activity Launch Options

Wait for Launch Completion
```bash
# Wait for activity to launch completely
adb shell am start -W \
  -n com.example.app/.ui.MainActivity

Launch with Specific User
Launch as specific user (multi-user devices)
adb shell am start --user 0 \
  -n com.example.app/.ui.MainActivity
```

Force New Task
Force new task creation
adb shell am start \
  --activity-clear-top \
  -n com.example.app/.ui.MainActivity

Intent Data Types

String Extras
--es "key" "value"          # String extra
--esa "key" "val1,val2"     # String array

Numeric Extras
--ei "key" 123              # Integer extra
--el "key" 1234567890       # Long extra
--ef "key" 3.14             # Float extra
--ed "key" 3.14159          # Double extra
```

Boolean and URI
--ez "key" true             # Boolean extra
-d "https://example.com"    # URI data

Security Testing Tips

Finding Exported Activities
Search for exported activities in AndroidManifest.xml
grep -E 'activity.*exported="true"' AndroidManifest.xml

Find activities with intent filters
grep -A 10 '<activity' AndroidManifest.xml | grep -B 5 'intent-filter'

Monitoring Activity Launches
Monitor activity manager logs
adb logcat | grep ActivityManager

View current activity stack
adb shell dumpsys activity activities

View specific app's activities
adb shell dumpsys activity activities | grep com.example.app

Common Testing Scenarios

1. **URL Validation Bypass** - Test custom schemes with unexpected protocols
2. **Parameter Injection** - Test activities with malformed or unexpected parameters
3. **Authorization Bypass** - Test restricted activities with crafted intents
4. **Deep Link Hijacking** - Test if activities properly validate incoming URLs
5. **Payment Flow Manipulation** - Test financial activities with modified amounts
6. **Age Gate Bypass** - Test if age verification can be circumvented

Security Considerations

- Only test applications you own or have explicit permission to test
- Use safe test data and avoid real financial transactions
- Test in isolated environments to prevent unintended consequences
- Follow responsible disclosure practices for any vulnerabilities found
- Ensure compliance with bug bounty program guidelines
- Document all testing steps and findings properly

Legal Notice

This reference is for authorized security testing only. Users must have explicit permission to test target applications and must follow all applicable laws, regulations, and bug bounty program terms.

import qrcode

data = "http://secure-login-example.com/verify-account"

qr = qrcode.make(data)

qr.save("phishing_test_qr.png")

print("Phishing test QR created successfully!")
print("File name: phishing_test_qr.png")
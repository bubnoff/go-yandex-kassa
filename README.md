1) Download certification chain ( http://crls.yamoney.ru/yamoney_chain.p7b ) and install to your server
    openssl pkcs7 -inform DER -outform PEM -in yamoney_chain.p7b -print_certs > ymca.crt

    then

    sudo mkdir /usr/share/ca-certificates/extra
    sudo cp ymca.crt /usr/share/ca-certificates/extra/ymca.crt
    sudo dpkg-reconfigure ca-certificates


2) Get yandex certificate https://tech.yandex.com/money/doc/payment-solution/shop-config/intro-docpage/

3) Add this go package

    resp, err := yandex.GetBalance()

    fmt.Println(resp.Error, resp.status)


     resp, err := yandex.PayOnPhone(50, "79995556677")

     fmt.Println(resp.Error, resp.status)
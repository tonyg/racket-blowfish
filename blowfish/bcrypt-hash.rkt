#lang racket/base

(provide bcrypt-hash bcrypt-pbkdf bcrypt-bytes-xor)

(require sha)
(require "main.rkt")

(define bcrypt-hash-seed
  (let ((bs (bytes-copy #"OxychromaticBlowfishSwatDynamite")))
    (uint32-bytes-big->native-endian! bs)
    bs))

(define (bcrypt-hash pass salt)
  (define c (blf-init))
  (blf-key/salt c pass salt)
  (for [(i (in-range 64))]
    (blf-key c salt)
    (blf-key c pass))
  (define cdata (bytes-copy bcrypt-hash-seed))
  (for [(i (in-range 64))] (blf-enc c cdata))
  cdata)

(define (bcrypt-bytes-xor a b)
  (define c (make-bytes (bytes-length a)))
  (for [(i (in-range (bytes-length c)))]
    (bytes-set! c i (bitwise-xor (bytes-ref a i) (bytes-ref b i))))
  c)

(define (bcrypt-pbkdf pass salt keylen rounds)
  (define hashsize 32)
  ;; Follow bcrypt_pbkdf.c in accepting "nothing crazy"
  ;;
  (when (zero? rounds) (error 'bcrypt-pbkdf "Zero rounds"))
  (when (zero? (bytes-length pass)) (error 'bcrypt-pbkdf "Empty passphrase"))
  (when (zero? (bytes-length salt)) (error 'bcrypt-pbkdf "Empty salt"))
  (when (zero? keylen) (error 'bcrypt-pbkdf "Empty output requested"))
  (when (> keylen (* hashsize hashsize)) (error 'bcrypt-pbkdf "Too much output requested"))

  (define nblocks (quotient (+ keylen 31) 32)) ;; round up
  (define hpass (sha512 pass))
  (define output (make-bytes keylen))

  (for [(block (in-range 1 (+ nblocks 1)))]
    (define count (integer->integer-bytes block 4 #f #t))
    (define hsalt (sha512 (bytes-append salt count)))
    (define out (bcrypt-hash hpass hsalt))
    (define tmp out)
    (for [(j (in-range 1 rounds))]
      (set! hsalt (sha512 tmp))
      (set! tmp (bcrypt-hash hpass hsalt))
      (set! out (bcrypt-bytes-xor out tmp))
      (for [(i (in-range (bytes-length out)))]
        (define idx (+ (* i nblocks) block -1))
        (when (< idx keylen)
          (bytes-set! output idx (bytes-ref out i))))))

  output)

(module+ test
  (require rackunit)
  (require (only-in racket/string string-append*))
  (require (only-in openssl/sha1 hex-string->bytes))

  ;; Test vectors courtesy of
  ;; https://github.com/DaGenix/rust-crypto/blob/master/src/bcrypt_pbkdf.rs

  (define (unhex . strs)
    (hex-string->bytes (string-append* strs)))

  (check-equal? (bcrypt-hash (unhex
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000")
                             (unhex
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"))
                (unhex "460286e972fa833f8b1283ad8fa919fa"
                       "29bde20e23329e774d8422bac0a7926c"))

  (check-equal? (bcrypt-hash (unhex
                              "000102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f"
                              "202122232425262728292a2b2c2d2e2f"
                              "303132333435363738393a3b3c3d3e3f")
                             (unhex
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"))
                (unhex "b0b229dbc6badef0e1da2527474a8b28"
                       "888f8b061476fe80c32256e1142dd00d"))

  (check-equal? (bcrypt-hash (unhex
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000"
                              "00000000000000000000000000000000")
                             (unhex
                              "000102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f"
                              "202122232425262728292a2b2c2d2e2f"
                              "303132333435363738393a3b3c3d3e3f"))
                (unhex "b62b4e367d3157f5c31e4d2cbafb2931"
                       "494d9d3bdd171d55cf799fa4416042e2"))

  (check-equal? (bcrypt-hash (unhex
                              "000102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f"
                              "202122232425262728292a2b2c2d2e2f"
                              "303132333435363738393a3b3c3d3e3f")
                             (unhex
                              "000102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f"
                              "202122232425262728292a2b2c2d2e2f"
                              "303132333435363738393a3b3c3d3e3f"))
                (unhex "c6a95fe6413115fb57e99f757498e85d"
                       "a3c6e1df0c3c93aa975c548a344326f8"))

  (check-equal? (bcrypt-pbkdf #"password" #"salt" 32 4)
                (unhex "5bbf0cc293587f1c3635555c27796598"
                       "d47e579071bf427e9d8fbe842aba34d9"))

  (check-equal? (bcrypt-pbkdf #"password" #"\0" 16 4)
                (unhex "c12b566235eee04c212598970a579a67"))

  (check-equal? (bcrypt-pbkdf #"\0" #"salt" 16 4)
                (unhex "6051be18c2f4f82cbf0efee5471b4bb9"))

  (check-equal? (bcrypt-pbkdf #"password\x00" #"salt\x00" 32 4)
                (unhex "7410e44cf4fa07bfaac8a928b1727fac"
                       "001375e7bf7384370f48efd121743050"))

  (check-equal? (bcrypt-pbkdf #"pass\x00wor" #"sa\x00l" 16 4)
                (unhex "c2bffd9db38f6569efef4372f4de83c0"))

  (check-equal? (bcrypt-pbkdf #"pass\x00word" #"sa\x00lt" 16 4)
                (unhex "4ba4ac3925c0e8d7f0cdb6bb1684a56f"))

  (check-equal? (bcrypt-pbkdf #"password" #"salt" 64 8)
                (unhex "e1367ec5151a33faac4cc1c144cd23fa"
                       "15d5548493ecc99b9b5d9c0d3b27bec7"
                       "6227ea66088b849b20ab7aa478010246"
                       "e74bba51723fefa9f9474d6508845e8d"))

  (check-equal? (bcrypt-pbkdf #"password" #"salt" 16 42)
                (unhex "833cf0dcf56db65608e8f0dc0ce882bd"))

  (check-equal? (bcrypt-pbkdf #"Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
                              #"salis\x00"
                              16
                              8)
                (unhex "10978b07253df57f71a162eb0e8ad30a"))

  (check-equal? (bcrypt-pbkdf (unhex "0db3ac94b3ee53284f4a22893b3c24ae")
                              (unhex "3a62f0f0dbcef823cfcc854856ea1028")
                              16
                              8)
                (unhex "204438175eee7ce136c91b49a67923ff"))

  (check-equal? (bcrypt-pbkdf (unhex "0db3ac94b3ee53284f4a22893b3c24ae")
                              (unhex "3a62f0f0dbcef823cfcc854856ea1028")
                              256
                              8)
                (unhex "2054b9fff34e3721440334746828e9ed"
                       "38de4b72e0a69adc170a13b5e8d64638"
                       "5ea4034ae6d26600ee2332c5ed40ad55"
                       "7c86e3403fbb30e4e1dc1ae06b99a071"
                       "368f518d2c426651c9e7e437fd6c915b"
                       "1bbfc3a4cea71491490ea7afb7dd0290"
                       "a678a4f441128db1792eab2776b21eb4"
                       "238e0715add4127dff44e4b3e4cc4c4f"
                       "9970083f3f74bd698873fdf648844f75"
                       "c9bf7f9e0c4d9e5d89a7783997492966"
                       "616707611cb901de31a19726b6e08c3a"
                       "8001661f2d5c9dcc33b4aa072f90dd0b"
                       "3f548d5eeba4211397e2fb062e526e1d"
                       "68f46a4ce256185b4badc2685fbe78e1"
                       "c7657b59f83ab9ab80cf9318d6add1f5"
                       "933f12d6f36182c8e8115f68030a1244"))

  )

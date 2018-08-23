#lang racket/base

(provide (struct-out Blowfish-context)
         blf-init
         blf-key
         blf-key/salt
         blf-enc
         blf-dec
         blf-blocksize
         uint32-bytes-big->native-endian!
         uint32-bytes-native->big-endian!)

(require ffi/unsafe)
(require ffi/unsafe/define)

(struct Blowfish-context (bytes) #:transparent)

(define (local-lib-dirs)
  (list (build-path (collection-path "blowfish")
		    "private"
		    "compiled"
		    "native"
		    (system-library-subpath))))

(define blowfish-lib (ffi-lib "blowfish" #:get-lib-dirs local-lib-dirs))
(define-ffi-definer define-blowfish blowfish-lib)

(define-blowfish Blowfish_context_size (_fun -> _uint))
(define-blowfish Blowfish_initstate (_fun _bytes -> _void))
(define-blowfish Blowfish_expand0state (_fun _bytes _bytes _uint16 -> _void))
(define-blowfish Blowfish_expandstate (_fun _bytes _bytes _uint16 _bytes _uint16 -> _void))
(define-blowfish Blowfish_encipher (_fun _bytes _pointer _pointer -> _void))
(define-blowfish Blowfish_decipher (_fun _bytes _pointer _pointer -> _void))
(define-blowfish Blowfish_stream2word (_fun _bytes _uint16 _pointer -> _uint32))
(define-blowfish blf_enc (_fun _bytes _pointer _uint16 -> _void))
(define-blowfish blf_dec (_fun _bytes _pointer _uint16 -> _void))

(module+ lowlevel
  (provide Blowfish_context_size
           Blowfish_initstate
           Blowfish_expand0state
           Blowfish_expandstate
           Blowfish_encipher
           Blowfish_decipher
           Blowfish_stream2word
           blf_enc
           blf_dec))

(define (blf-init)
  (define ctx (make-bytes (Blowfish_context_size)))
  (Blowfish_initstate ctx)
  (Blowfish-context ctx))

(define (blf-key c key)
  (Blowfish_expand0state (Blowfish-context-bytes c) key (bytes-length key)))

(define (blf-key/salt c key salt)
  (Blowfish_expandstate (Blowfish-context-bytes c) salt (bytes-length salt) key (bytes-length key)))

(define (uint32-bytes-big->native-endian! bs)
  (when (not (system-big-endian?))
    (for ((i (in-range 0 (bytes-length bs) 4)))
      (define n (integer-bytes->integer bs #f #t i (+ i 4)))
      (integer->integer-bytes n 4 #f #f bs i))))

(define (uint32-bytes-native->big-endian! bs)
  (when (not (system-big-endian?))
    (for ((i (in-range 0 (bytes-length bs) 4)))
      (define n (integer-bytes->integer bs #f #f i (+ i 4)))
      (integer->integer-bytes n 4 #f #t bs i))))

(define blf-blocksize 8)

(define (blf-enc c data)
  ;; Warning: ensure data is native-endian uint32s!
  (when (not (zero? (modulo (bytes-length data) blf-blocksize)))
    (error 'blf-enc "Expects a multiple of ~a bytes of data" blf-blocksize))
  (blf_enc (Blowfish-context-bytes c) data (quotient (bytes-length data) blf-blocksize)))

(define (blf-dec c data)
  ;; Warning: ensure data is native-endian uint32s!
  (when (not (zero? (modulo (bytes-length data) blf-blocksize)))
    (error 'blf-dec "Expects a multiple of ~a bytes of data" blf-blocksize))
  (blf_dec (Blowfish-context-bytes c) data (quotient (bytes-length data) blf-blocksize)))

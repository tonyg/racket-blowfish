#lang racket/base

(require racket/file)
(require dynext/file)
(require dynext/link)

(provide pre-installer)

(define (pre-installer collections-top-path blowfish-path)
  (define private-path (build-path blowfish-path "private"))

  (parameterize ((current-directory private-path))
    (define shared-object-target-path
      (build-path private-path "compiled" "native" (system-library-subpath)))
    (define shared-object-target
      (build-path shared-object-target-path (append-extension-suffix "blowfish")))

    (when (not (file-exists? shared-object-target))
      (make-directory* shared-object-target-path)
      (parameterize ((current-extension-linker-flags
		      (append (current-extension-linker-flags)
			      (list "-O3" "-fomit-frame-pointer" "-funroll-loops"))))
	(link-extension #f ;; not quiet
                        (list (build-path private-path "blowfish.c"))
			shared-object-target)))))

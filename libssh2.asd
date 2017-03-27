;;; -*- mode: Lisp; syntax: Common-Lisp; -*-

(defsystem "libssh2"
  :description "Trivial libssh2 bindings"
  :version      "0.1"
  :author       "Oleksii Shevchuk <alxchk@gmail.com>"
  :license      "Public Domain"
  :defsystem-depends-on ("cffi-grovel")
  :depends-on   ("babel"
                 "cffi"
                 "cl-fad"
                 "hu.dwim.logger"
                 "split-sequence"
                 "trivial-gray-streams"
                 "usocket")
  :serial       t
  :components   ((:module "src"
                  :serial t
                  :components ((:file "package")
                               (:file "logging")
                               (:file "types")
                               (:cffi-grovel-file "libssh2-libc-cffi")
                               (:file "util")
                               (:file "libssh2-cffi")
                               (:file "streams")
                               (:file "scp")
                               (:file "sftp")
                               (:file "solutions"))))
  :in-order-to ((test-op (test-op "libssh2.test"))))

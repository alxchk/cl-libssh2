;;; -*- mode: lisp; syntax: common-lisp; indent-tabs-mode: nil -*-

(defsystem "libssh2.test"
  :description "cl-libssh2 tests"
  :author       "Oleksii Shevchuk <alxchk@gmail.com>"
  :license      "Public Domain"
  :depends-on   ("libssh2"
                 "hu.dwim.stefil")
  :serial       t
  :components   ((:module "test"
                  :components
                  ((:file "package")
                   (:file "scp")
                   (:file "sftp"))))
  :perform (test-op (o c) (symbol-call :libssh2.test :run-all-tests)))

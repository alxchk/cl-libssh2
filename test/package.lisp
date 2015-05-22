;;; -*- mode: lisp; syntax: common-lisp; indent-tabs-mode: nil -*-

(in-package #:cl-user)

(defpackage #:libssh2.test
  (:use #:common-lisp #:libssh2 #:hu.dwim.stefil)
  (:export #:run-unit-tests
           #:run-integration-tests
           #:run-all-tests))

(in-package #:libssh2.test)

;; The suite 'unit' is used for real unit tests which just test the code
;; and don't depend on the presence of an SSH server
(defsuite* (unit :in root-suite))

;; The suite 'integration' is used for integration tests which depend on an
;; SSH server and some previously created users
(defsuite* (integration :in root-suite))

(defun run-all-tests ()
  (handler-case (progn
                  (unit)
                  (integration))
    (t () (uiop:quit -1))))

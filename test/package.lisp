;;; -*- mode: lisp; syntax: common-lisp; indent-tabs-mode: nil -*-

(in-package #:cl-user)

(defpackage #:libssh2.test
  (:use #:common-lisp #:libssh2 #:hu.dwim.stefil)
  (:export #:run-unit-tests
           #:run-integration-tests
           #:run-all-tests))

(in-package #:libssh2.test)

;; The suite 'u' is used for real unit tests which just test the code
;; and don't depend on the presence of an SSH server
(defsuite* (u :in root-suite))

;; The suite 'int' is used for integration tests which depend on an
;; SSH server and some previously created users
(defsuite* (int :in root-suite))


(defun run-unit-tests ()
  (funcall-test-with-feedback-message 'u))

(defun run-integration-tests ()
  (funcall-test-with-feedback-message 'u))

(defun run-all-tests ()
  (run-unit-tests)
  (run-integration-tests))

;;; -*- mode: lisp; syntax: common-lisp; indent-tabs-mode: nil -*-

(in-package #:libssh2.test)


(in-suite integration)

(deftest scp-copy-back-and-forth ()
  (with-ssh-connection sshc
      (*test-host*
     (libssh2:make-password-auth *user1* *password1*)
     :hosts-db *known-hosts-path*)
    (let ((test-file (asdf:system-relative-pathname (asdf:find-system :libssh2) "test/data/testfile.tgz"))
          (remote-name "/tmp/copied-to-remote.tgz")
          (final "/tmp/copied-back-from-remote.tgz")
          (md5 "3fee5a92e7d3a2c716e922434911aa7c")
          (stream/type  '(unsigned-byte 8)))
      ;; copy file to ssh host
      (with-open-file (in test-file
                          :direction :input
                          :element-type stream/type)
        (libssh2:with-scp-output (out sshc remote-name
                                  (file-length in))
          (cl-fad:copy-stream in out)))
      ;; copy back from ssh host
      (libssh2:with-scp-input (in sshc remote-name stat)
        (with-open-file (out final
                             :direction :output
                             :if-exists :supersede
                             :if-does-not-exist :create
                             :element-type stream/type)
          (cl-fad:copy-stream in out)))
      ;; calculate remote md5
      (libssh2:with-execute* (in sshc (format nil "md5sum ~a" test-file #+nil final))
        (let ((sums (loop for line = (read-line in nil)
                          while line
                          do (format t "~%<~A>~%" (split-sequence:split-sequence #\Space line))
                          collect (car (split-sequence:split-sequence #\Space line)))))
          (unless (every (lambda (s) (equal s md5)) sums)
            (error "MD5 sums of local and remote files differ")))))))

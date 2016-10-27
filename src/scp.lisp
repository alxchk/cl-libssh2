;; -*- mode: lisp; syntax: common-lisp -*-

(in-package :libssh2)

(defmethod scp-get (remote-name (local string) &optional (connection *ssh-connection*))
  (with-scp-input (in connection remote-name stat)
    (with-open-file (out local
                         :direction :output
                         :if-exists :supersede
                         :if-does-not-exist :create
                         :element-type '(unsigned-byte 8))
      (cl-fad:copy-stream in out))))

(defun scp-put (local-name remote-name &optional (connection *ssh-connection*))
  (with-open-file (in local-name
                      :direction :input
                      :element-type '(unsigned-byte 8))
    (with-scp-output (out connection remote-name
                      (file-length in))
      (cl-fad:copy-stream in out))))


(defmethod scp-get (remote-name (local stream) &optional (connection *ssh-connection*))
  (when (not (output-stream-p local))
    (error 'ssh-generic-error
           :code "BAD-STREAM-DIRECTION"
           :message "the given stream has to support output"))
  (when (not (equalp (stream-element-type local) '(unsigned-byte 8)))
    (error 'ssh-generic-error 
           :code "BAD-STREAM-ELEMENT-TYPE"
           :message "the given stream must have element type (unsigned-byte 8)"))
  (with-scp-input (in connection remote-name stat)
    (cl-fad:copy-stream in local)))

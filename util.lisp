(in-package libssh2)

;; From:
;;  http://common-lisp.net/~loliveira/ediware/hunchentoot/set-timeouts.lisp
(defun set-timeouts (usocket read-timeout write-timeout)
  "Sets up timeouts on the given USOCKET object.  READ-TIMEOUT is the
read timeout period, WRITE-TIMEOUT is the write timeout, specified in
\(fractional) seconds.  The timeouts can either be implemented using
the low-level socket options SO_RCVTIMEO and SO_SNDTIMEO or some
other, implementation specific mechanism.  On platforms that do not
support separate read and write timeouts, both must be equal or an
error will be signaled.  READ-TIMEOUT and WRITE-TIMEOUT may be NIL,
which means that the corresponding socket timeout value will not be
set."
  (declare (ignorable usocket read-timeout write-timeout))
  ;; add other Lisps here if necessary
  #+(or :sbcl :cmu)
  (unless (eql read-timeout write-timeout)
    (parameter-error "Read and write timeouts for socket must be equal."))
  #+:clisp
  (when read-timeout
    (socket:socket-options (usocket:socket usocket) :SO-RCVTIMEO read-timeout))
  #+:clisp
  (when write-timeout
    (socket:socket-options (usocket:socket usocket) :SO-SNDTIMEO write-timeout))
  #+:openmcl
  (when read-timeout
    (setf (ccl:stream-input-timeout (usocket:socket usocket))
          read-timeout))
  #+:openmcl
  (when write-timeout
    (setf (ccl:stream-output-timeout (usocket:socket usocket))
          write-timeout))
  #+:sbcl
  (when read-timeout
    (setf (sb-impl::fd-stream-timeout (usocket:socket-stream usocket))
          (coerce read-timeout 'single-float)))
  #+:cmu
  (setf (lisp::fd-stream-timeout (usocket:socket-stream usocket))
        (coerce read-timeout 'integer))
  #-(or :clisp :allegro :openmcl :sbcl :lispworks :cmu)
  (not-implemented 'set-timeouts))


(defun usocket-get-fd (uso)
	(slot-value (usocket:socket uso) 'sb-bsd-sockets::file-descriptor))



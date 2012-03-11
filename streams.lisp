(in-package libssh2)

;; CLOS FACADE: FOR BLOCKING STREAMS!! ;;

(define-condition libssh2-invalid-error-code (error)
	((code :type     keyword
				 :accessor code
				 :initarg  :code)))

(defun  throw-last-error (session)
	(multiple-value-bind (message code)
			(session-last-error session)
		(error 'ssh-generic-error 
					 :message message
					 :code    code)))
	 
(defmacro with-last-error ((session error-type) &rest args)
	`(multiple-value-bind (message code)
			 (session-last-error ,session)
		 (error (quote ,error-type)
						:message message
						:code    code
						,@args)))

(eval-when (:compile-toplevel :load-toplevel :execute)	
	(defvar *default-errors-list*
		(remove :ERROR-NONE (foreign-enum-keyword-list '+ERROR-CODE+))))
	
(defvar *errors-list* *default-errors-list*)

(defmacro result-or-error (&body body)
	`(let ((results (multiple-value-list (progn ,@body)))
				 (throwable-errors *errors-list*))
		 (if (find (car results)
							 throwable-errors)
				 (error 'libssh2-invalid-error-code :code (car results))
				 (values-list results))))

(defclass auth-data ()
	((login    :type      string
					   :initarg   :login
					   :initform  ""
					   :reader    login)))
	 
(defclass ssh-connection ()
	((session     :type     +session+
						    :initarg  :session
						    :initform (null-pointer)
						    :reader   session)
	 (socket      :type     usocket:socket
						    :initarg  :socket
						    :accessor socket)
	 (host        :type     string
								:initarg  :host
						    :accessor host)
	 (port        :type     int
								:initarg  :port
						    :accessor port)
	 (hosts-db    :type     string
								:initarg  :hosts-db
								:accessor hosts-db)
	 (auth-passed :type     boolean
								:initform nil
								:accessor auth-passed)))

(define-condition ssh-handshake-error (ssh-generic-error) ())

(define-condition ssh-bad-hostkey (error)
	((reason :type      +CHECK-VERDICT+
					 :accessor  reason
					 :initarg   :reason)
	 (hash   :type      string
					 :accessor  hash
					 :initarg   :hash)))

(defmethod create-ssh-connection (host (hosts-db string) 
																	&key 
																	(port 22) 
																	(read-timeout 5) 
																	(write-timeout 5))
	(let ((new-session nil)
				(new-socket  nil)
				(retval      :ERROR-NONE))
		(unwind-protect 
				 (progn
					 (setq new-session (session-init))
					 (setq new-socket (usocket:socket-connect host port))
					 (set-timeouts new-socket read-timeout write-timeout)
					 (session-set-blocking new-session :BLOCKING)
					 
					 (setq retval 
								 (session-handshake new-session (usocket-get-fd new-socket)))
					 
					 (if (eq retval :ERROR-NONE)
							 (make-instance 'ssh-connection
															:session  new-session
															:socket   new-socket
															:host     host
															:port     port
															:hosts-db hosts-db)
							 (throw-last-error new-session)))
			(unless (eq retval :ERROR-NONE)
				(unless (null-pointer-p new-session)
					(session-free new-session))
				(unless (null new-socket)
					(usocket:socket-close new-socket))
				nil))))
				

(defmethod destroy-ssh-connection ((ssh ssh-connection) &key (description "") (lang ""))
	(unwind-protect
			 (session-disconnect (session ssh) 
													 :description description
													 :lang   lang)
		(progn
			(usocket:socket-close (socket ssh))
			(session-free (session ssh)))))

(defmacro with-ssh-connection (session (&rest connection-args) &body body)
	`(let ((,session (create-ssh-connection ,@connection-args)))
		 (unwind-protect
					(handler-bind ((libssh2-invalid-error-code 
													(lambda (condition) 
														(declare (ignore condition))
														(throw-last-error (session ,session)))))
						,@body)
			 (destroy-ssh-connection ,session))))

(defmethod ssh-session-key ((ssh ssh-connection))
	(session-hostkey (session ssh)))

(defmethod ssh-host+port-format ((ssh ssh-connection))
	(format nil "[~a]:~a"
					(host ssh)
					(port ssh)))

(defclass auth-password (auth-data)
	((password :type      string
						 :initarg   :password
						 :initform  ""
						 :reader    password)))

(defmethod ssh-verify-session ((ssh ssh-connection))
	(with-known-hosts (known-hosts ((session ssh) (hosts-db ssh)))
		(let* ((host-key        (ssh-session-key ssh))
					 (host-key-status (known-hosts-check known-hosts
																							 (host ssh)
																							 host-key
																							 :port (port ssh))))
			(if (eq host-key-status :MATCH)
					t
					(restart-case 
							(error 'ssh-bad-hostkey 
										 :reason host-key-status
										 :key (session-hostkey-fingerprint (session ssh)))
						(accept () t)
						(drop () nil)
						(accept-once  (&optional (comment "")) 
							(progn 
								(known-hosts-add known-hosts (ssh-host+port-format ssh) host-key 
																 :comment comment)
								t))
						(accept-always (&optional (comment "")) 
							(progn 
								(known-hosts-add known-hosts (ssh-host+port-format ssh) host-key 
																 :comment comment)
								(known-hosts-writefile known-hosts (hosts-db ssh))
								t)))))))

(defmethod authentication-methods ((ssh ssh-connection) (login string))
	(session-auth-methods-list (session ssh) login))

(defmethod authentication :around ((ssh ssh-connection) (auth auth-data))
	(if (auth-passed ssh)
			t
			(if (ssh-verify-session ssh)
					(setf (auth-passed ssh)
								(eq
								 (result-or-error
									 (call-next-method)) :ERROR-NONE)))))

(defmethod authentication ((ssh ssh-connection) (auth auth-password))
	(user-auth-password (session  ssh)
											(login    auth)
											(password auth)))

(defclass auth-publickey (auth-data)
	((public-key  :type     string
							  :initarg  :public-key
							  :initform "id_rsa.pub"
							  :accessor public-key)
	 (private-key :type     string
								:initarg  :private-key
								:initform "id_rsa"
								:accessor private-key)
	 (password    :type     string
								:initarg  :password
								:initform ""
								:accessor password)))

(defmethod authentication ((ssh ssh-connection) (auth auth-publickey))
	(with-slots (login public-key private-key password) auth
		(user-auth-publickey (session ssh) 
												 login public-key private-key password)))

(defclass auth-agent (auth-data) ())

(defmethod authentication ((ssh ssh-connection) (auth auth-agent))
	(let ((agent (agent-init (session ssh)))
				(username (login auth)))
		(unwind-protect
				 (if (and agent
									(eq (agent-connect agent)
											:ERROR-NONE))
						 (let ((next-identity (agent-identities-iterator agent)))
							 (when next-identity
								 (with-foreign-string (fs-username username)
									 (loop for identity = (funcall next-identity)
											while identity do
												(if (eq
														 (--agent-userauth agent fs-username identity)
														 :ERROR-NONE)
														(return t))))))
						 (throw-last-error (session ssh)))
			(when agent 
				(agent-free agent)))))

(defun make-publickey-auth (login directory private-key-name &optional (password ""))
	(let ((private-key 
				 (namestring (make-pathname :directory directory
																		:name private-key-name)))
				(public-key 
				 (namestring (make-pathname :directory directory
																		:name private-key-name
																		:type "pub"))))
		(make-instance 'auth-publickey 
									 :login       login
									 :public-key  public-key
									 :private-key private-key
									 :password    password)))

(defun make-agent-login (login)
	(make-instance 'auth-agent 
								 :login login))

(defun make-password-login (login password)
	(make-instance 'auth-password 
								 :login    login
								 :password password))

(defvar *ssh-channel-buffer-size* 1400)

(defclass ssh-channel-stream 
		(fundamental-binary-input-stream
		 fundamental-binary-output-stream
		 fundamental-character-output-stream
		 fundamental-character-input-stream
		 trivial-gray-stream-mixin)
	
	((socket        :initarg  :socket
									:accessor socket)
	 (channel       :type     +CHANNEL+
						      :initarg  :channel
						      :accessor channel)
	 (input-buffer  :initform (make-shareable-byte-vector
														 *ssh-channel-buffer-size*)
								  :accessor input-buffer)
	 (input-size    :initform 0
									:accessor input-size
									:type     int)
	 (output-buffer :initform (make-shareable-byte-vector
														 *ssh-channel-buffer-size*)
								  :accessor output-buffer)
	 (output-size   :initform 0
									:accessor output-size
									:type     int)
	 (intput-pos    :type     int
									:initform 0
									:accessor input-pos)
	 (output-pos    :type     int
									:initform 0
									:accessor output-pos)))

(defmethod stream-element-type ((stream ssh-channel-stream))
	(declare (ignore stream))
	'(unsigned-byte 8))

(defmethod open-stream-p ((stream ssh-channel-stream))
	(not (null-pointer-p (channel stream))))

(defmethod stream-listen ((stream ssh-channel-stream))
	(listen (usocket:socket-stream (socket stream))))

(defmethod stream-read-byte ((stream ssh-channel-stream))
	(cond 
		((< (input-pos stream) (input-size stream))
		 (prog1 (elt (input-buffer stream) (input-pos stream))
			 (incf (input-pos stream))))
		(t (progn
				 (let ((amount (channel-read (channel stream) 
																		 (input-buffer stream))))
					 (when (> amount 0)
						 (setf (input-pos   stream)  1)
						 (setf (input-size  stream)  amount)
						 (elt  (input-buffer stream) 0)))))))

(defmethod stream-read-sequence ((stream ssh-channel-stream) thing start end &key)
	;; UNTESTED
	(let ((request-size          (- end start))
				(buffered-portion-size (- (input-size stream) (input-pos stream))))

		(labels 
				((buffer-to-output ()
					 (let ((replaced-size (min buffered-portion-size request-size)))
						 (replace thing (input-buffer stream)
											:start1 start :end1 buffered-portion-size
											:start2 (input-pos stream) :end2 (+ (input-pos stream)
																													buffered-portion-size))
						 (incf start          replaced-size)
						 (decf request-size   replaced-size)))
				 
				 (fill-buffer-and-output ()
					 (setf (input-size stream)
								 (channel-read (channel stream)
															 (input-buffer stream)))
								 
					 (setf (input-pos  stream) 0)
						 
					 (buffer-to-output)
						 
					 (if (> request-size 0)
							 (fill-buffer-and-output)
							 (progn
								 (buffer-to-output)
								 start))))
				 
			(buffer-to-output)
			(if (> request-size 0)
					(fill-buffer-and-output)))))

(defmethod stream-read-line ((stream ssh-channel-stream))
	(let ((output '()))
		(labels
				((repeat-not-wait ()
					 ;; Search for new line in cached tail
					 (let* ((nl-pos (position (char-code '#\Newline)
																		(input-buffer stream)
																		:start (input-pos  stream)
																		:end   (input-size stream)))
									(co-end (if nl-pos nl-pos (input-size stream))))
						 ;; Save substring or whole vector if any
						 (when (> (input-size stream) 0)
							 (push (subseq (input-buffer stream) 
														 (input-pos stream)
														 co-end)
										 output))
						 
						 (if nl-pos
								 ;; If newline found - save position and return concatenated string
								 (prog1
										 (babel:octets-to-string
											(apply #'concatenate
														 (cons '(VECTOR
																		 (UNSIGNED-BYTE
																			8))
																	 (reverse output))))
									 (setf (input-pos stream) (+ 1 co-end))
									 (setf output '()))
								 
								 ;; If not - try to catch next portion
								 (multiple-value-bind (amount code)
										 (channel-read (channel stream) (input-buffer stream))
									 (cond 
										 ((and (= amount 0) (eq code :ERROR-EAGAIN))
											;; Just wait for next portion
											code)
										 ((> amount 0)
											;; Save portion, don't care about error code. 
											;; Care about it on next iteration
											(progn 
												(setf (input-pos  stream) 0)
												(setf (input-size stream) amount)
												(repeat-not-wait)))
										 (t 
											(if (not (null output))
													;; Return last cached data
													(prog1
															(babel:octets-to-string
															 (apply #'concatenate
																			(cons '(VECTOR
																							(UNSIGNED-BYTE
																							 8))
																						(reverse output))))
														(setf (input-size stream) 0
																	(input-pos  stream) 0)
														(setf output '()))
													;; Time to return nil
													nil))))))))
			(repeat-not-wait))))

(defmethod stream-force-output ((stream ssh-channel-stream))
	(with-slots (channel output-buffer output-pos output-size) stream
		(let ((amount (channel-write channel
																 output-buffer
																 :start output-pos
																 :end   output-size)))
			(incf output-pos amount)
			(if (= output-pos
						 output-size)
					(setf output-pos  0
								output-size 0 ))
			amount)))
							
(defmethod stream-finish-output* ((stream ssh-channel-stream) &key (dont-send-eof nil))
	(with-slots (socket channel output-buffer output-pos output-size) stream
		(let ((amount 
					 (channel-write channel
													output-buffer
													:start output-pos
													:end   output-size)))
			
			(incf output-pos amount)
			(if (= output-pos
						 output-size)
					(setf output-pos  0
								output-size 0 ))
			(if dont-send-eof
					amount
					(channel-send-eof channel)))))

(defmethod stream-finish-output ((stream ssh-channel-stream))						
	(stream-finish-output* stream))

(defmethod stream-write-byte ((stream ssh-channel-stream) byte)
	(with-slots (output-pos output-size output-buffer) stream
			(if (>= output-size (length output-buffer))
					(stream-finish-output* stream :dont-send-eof t))
			(when (< output-size (length output-buffer))
				(prog1
						(setf (aref output-buffer output-size) byte)
					(incf output-size 1)))))

(defmethod stream-write-char ((stream ssh-channel-stream) char)
	(stream-write-byte stream (char-code char)))

(defmethod stream-write-sequence ((stream ssh-channel-stream) (sharable-sequence string) start end &key)
	;; If string passed, then flush previous buffer if any
	;; Then directly write this one
	(stream-finish-output* stream :dont-send-eof t)
	(channel-write-string (channel stream) 
												sharable-sequence
												:start start
												:end   end))

(defmethod stream-write-sequence ((stream ssh-channel-stream) sequence start end &key)
	(with-slots (output-pos output-size output-buffer) stream
		(let ((max-output-buffer     (length output-buffer))
					(requested-output-size (- end start)))
			(labels
					((push-to-stream ()
						 (let ((pushable-chunk-size (min requested-output-size
																						 max-output-buffer)))
							 (if (>= (+ output-size pushable-chunk-size)
											 max-output-buffer)
									 (stream-finish-output* stream :dont-send-eof t))

							 (when (< (+ output-size pushable-chunk-size)
												max-output-buffer)
								 (progn
									 (replace output-buffer sequence 
														:start1 output-size
														:end1   (+ output-size
																			 pushable-chunk-size)
														:start2 start
														:end2   (+ start
																			 pushable-chunk-size))
									 (incf output-size pushable-chunk-size)
									 (decf requested-output-size pushable-chunk-size)
									 (incf start pushable-chunk-size)
									 (when (> requested-output-size 0)
										 (push-to-stream)))))))
				(push-to-stream)
				sequence))))
				
(defmethod close ((stream ssh-channel-stream) &key abort)
	(let ((channel (channel stream)))
		(when (not (null-pointer-p channel))
			(unless abort
				(stream-force-output stream)
				(channel-flush channel))
			
			(channel-close channel)
			(channel-free channel))))

(defmethod execute ((ssh ssh-connection) (command string))
	(with-slots (socket session) ssh
		(let ((new-channel 
					 (channel-open session)))
			(if (pointerp new-channel)
					(if (not (null-pointer-p new-channel))
							(let ((retval (channel-exec new-channel command)))
								(if (eq retval :ERROR-NONE)
										(make-instance 'ssh-channel-stream
																	 :socket  socket
																	 :channel new-channel)
										(throw-last-error session)))
							(throw-last-error session))
					(throw-last-error session)))))

(defmacro with-execute (command (ssh-connection stdio-stream)
												&body body)
	`(let ((,stdio-stream (execute ,ssh-connection ,command)))
		 (unwind-protect
					(let ((body-retval
								 (progn ,@body)))
						(values-list 
						 (list body-retval
									 (channel-exit-status (channel ,stdio-stream)))))
			 (close ,stdio-stream))))

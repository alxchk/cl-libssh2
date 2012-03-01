(ql:quickload :cffi)
(ql:quickload :usocket)
(ql:quickload :trivial-gray-streams)
(ql:quickload :babel)
(ql:quickload :split-sequence)

(defpackage libssh2
	(:use :cffi 
				:cl :cl-user
				:trivial-gray-streams))

(in-package libssh2)

(defun print-memory (addr size)
	(format t "~{~x ~}" 
					(loop for i below size
						 collect (mem-aref addr :unsigned-char i))))
 
(define-foreign-library libssh2
	(t (:default "libssh2")))

(use-foreign-library libssh2)

(defcenum +DISCONNECT-CODE+
	(:HOST-NOT-ALLOWED-TO-CONNECT					 1  ) 
	(:PROTOCOL-ERROR											 2	) 
	(:KEY-EXCHANGE-FAILED									 3	) 
	(:RESERVED														 4	) 
	(:MAC-ERROR														 5	) 
	(:COMPRESSION-ERROR										 6	) 
	(:SERVICE-NOT-AVAILABLE								 7	) 
	(:PROTOCOL-VERSION-NOT-SUPPORTED			 8	) 
	(:HOST-KEY-NOT-VERIFIABLE							 9	) 
	(:CONNECTION-LOST											 10	) 
	(:BY-APPLICATION											 11	) 
	(:TOO-MANY-CONNECTIONS								 12	) 
	(:AUTH-CANCELLED-BY-USER							 13	) 
	(:NO-MORE-AUTH-METHODS-AVAILABLE			 14	) 
	(:ILLEGAL-USER-NAME										 15	)) 

(defcenum +ERROR-CODE+
	(:ERROR-NONE										 0	) 
	(:ERROR-SOCKET-NONE							 -1	) 
	(:ERROR-BANNER-RECV							 -2	) 
	(:ERROR-BANNER-SEND							 -3	) 
	(:ERROR-INVALID-MAC							 -4	) 
	(:ERROR-KEX-FAILURE							 -5	) 
	(:ERROR-ALLOC										 -6	) 
	(:ERROR-SOCKET-SEND							 -7	) 
	(:ERROR-KEY-EXCHANGE-FAILURE		 -8	) 
	(:ERROR-TIMEOUT									 -9	) 
	(:ERROR-HOSTKEY-INIT						 -10) 
	(:ERROR-HOSTKEY-SIGN						 -11) 
	(:ERROR-DECRYPT									 -12) 
	(:ERROR-SOCKET-DISCONNECT				 -13) 
	(:ERROR-PROTO										 -14) 
	(:ERROR-PASSWORD-EXPIRED				 -15) 
	(:ERROR-FILE										 -16) 
	(:ERROR-METHOD-NONE							 -17) 
	(:ERROR-AUTHENTICATION-FAILED		 -18) 
	(:ERROR-PUBLICKEY-UNVERIFIED		 -19) 
	(:ERROR-CHANNEL-OUTOFORDER			 -20) 
	(:ERROR-CHANNEL-FAILURE					 -21) 
	(:ERROR-CHANNEL-REQUEST-DENIED	 -22) 
	(:ERROR-CHANNEL-UNKNOWN					 -23) 
	(:ERROR-CHANNEL-WINDOW-EXCEEDED	 -24) 
	(:ERROR-CHANNEL-PACKET-EXCEEDED	 -25) 
	(:ERROR-CHANNEL-CLOSED					 -26) 
	(:ERROR-CHANNEL-EOF-SENT				 -27) 
	(:ERROR-SCP-PROTOCOL						 -28) 
	(:ERROR-ZLIB										 -29) 
	(:ERROR-SOCKET-TIMEOUT					 -30) 
	(:ERROR-SFTP-PROTOCOL						 -31) 
	(:ERROR-REQUEST-DENIED					 -32) 
	(:ERROR-METHOD-NOT-SUPPORTED		 -33) 
	(:ERROR-INVAL										 -34) 
	(:ERROR-INVALID-POLL-TYPE				 -35) 
	(:ERROR-PUBLICKEY-PROTOCOL			 -36) 
	(:ERROR-EAGAIN									 -37) 
	(:ERROR-BUFFER-TOO-SMALL				 -38) 
	(:ERROR-BAD-USE									 -39) 
	(:ERROR-COMPRESS								 -40) 
	(:ERROR-OUT-OF-BOUNDARY					 -41) 
	(:ERROR-AGENT-PROTOCOL					 -42) 
	(:ERROR-SOCKET-RECV							 -43) 
	(:ERROR-ENCRYPT									 -44) 
	(:ERROR-BAD-SOCKET							 -45)) 

(defcenum +DISCONNECT-CODE+
	(:HOST-NOT-ALLOWED-TO-CONNECT					1 ) 
	(:PROTOCOL-ERROR											2	) 
	(:KEY-EXCHANGE-FAILED									3	) 
	(:RESERVED														4	) 
	(:MAC-ERROR														5	) 
	(:COMPRESSION-ERROR										6	) 
	(:SERVICE-NOT-AVAILABLE								7	) 
	(:PROTOCOL-VERSION-NOT-SUPPORTED			8	) 
	(:HOST-KEY-NOT-VERIFIABLE							9	) 
	(:CONNECTION-LOST											10) 
	(:BY-APPLICATION											11) 
	(:TOO-MANY-CONNECTIONS								12) 
	(:AUTH-CANCELLED-BY-USER							13) 
	(:NO-MORE-AUTH-METHODS-AVAILABLE			14) 
	(:ILLEGAL-USER-NAME										15))

(define-condition ssh-generic-error (error)
	((message :type     string
						:initarg  :message
						:accessor message)
	 (code    :type     +ERROR-CODE+
						:accessor code
						:initarg  :code)))

(defmethod print-object ((sge ssh-generic-error) stream)
	(format stream "Libssh2: ~a (~a)" (message sge) (code sge)))
					
(defmacro repeat-and-wait-until-complete ((socket &optional (timeout 10)) &body body)
	`(let ((retval :ERROR-NONE))
		 (labels 
				 ((again ()
						(if (eq (setq retval 
													(progn
														,@body))
										:ERROR-EAGAIN)
								(progn
									(usocket:wait-for-input ,socket :timeout ,timeout)
									(again))
								retval)))
			 (again))))

(defcfun ("libssh2_init" library-init) +ERROR-CODE+)
(defcfun ("libssh2_exit" library-exit) :void)

(defctype +session+ :pointer)
(defcfun ("libssh2_session_init_ex" session-init-ex) +session+
	(alloc :pointer) (free :pointer) (realloc :pointer) (abstract :pointer))
(defcfun ("libssh2_session_free" session-free) +ERROR-CODE+
	(session +session+))

(defcfun ("libssh2_session_last_error" --session-last-error) +ERROR-CODE+
	(session +session+) 
	(error-message :pointer) (error-message-buffer-size :pointer)
	(ownership :int))

(defun session-last-error (session)
	(with-foreign-objects ((fo-error-message-buffer-ptr   :pointer 1)
												 (fo-error-message-buffer-size  :int     1))
		(let ((retval (--session-last-error session 
																				fo-error-message-buffer-ptr
																				fo-error-message-buffer-size 
																				0)))
			(let ((error-message-ptr  (mem-aref fo-error-message-buffer-ptr :pointer 0)))
				(values-list (list (convert-from-foreign error-message-ptr :string)
													 retval))))))


(defcfun ("libssh2_session_last_errno" session-last-errno) +ERROR-CODE+
	(session +session+))

(defbitfield +TRACE-OPTIONS+
	(.TRANS.    2)
	(.KEX.      4)
	(.AUTH.     8)
	(.CONN.     16)
	(.SCP.      32)
	(.SFTP.     64)
	(.ERROR.    128)
	(.PUBLICKEY 256)
	(.SOCKET    512))
	
(defcfun ("libssh2_trace" library-trace) :void
	(session +session+) (options +TRACE-OPTIONS+))

(defcenum +BLOCKING+
	(:BLOCKING     1)
	(:NON-BLOCKING 0))

(defcfun ("libssh2_session_set_blocking" session-set-blocking) :void
	(session +session+) (blocking +BLOCKING+))

(defun session-init ()
	(let ((session (session-init-ex (null-pointer)
																	(null-pointer)
																	(null-pointer)
																	(null-pointer))))
		(session-set-blocking session :NON-BLOCKING)
		session))


(defcfun ("libssh2_session_disconnect_ex" --session-disconnect) +ERROR-CODE+
	(session +session+) (reason +DISCONNECT-CODE+) (description :string) (lang :string))

(defun session-disconnect (session &key
													 (reason :AUTH-CANCELLED-BY-USER)
													 (description "")
													 (lang ""))
	(with-foreign-strings ((fs-description description)
												 (fs-lang        lang))
		(--session-disconnect session reason fs-description fs-lang)))

(defmacro with-session ( (session) &body body )
	`(let ((,session (session-init)))
		 (if (not (null-pointer-p ,session))
				 (unwind-protect 
							(progn
								,@body)
					 (session-free ,session))
				 (error "Couldn't create session"))))

(defun usocket-get-fd (uso)
	(slot-value (usocket:socket uso) 'sb-bsd-sockets::file-descriptor))

(defcfun ("libssh2_session_handshake" session-handshake) +ERROR-CODE+
	(session +session+) (socket :int))

(defcfun ("libssh2_userauth_list" --session-auth-methods-list) :string
	(session +session+) (username :string) (username-length :unsigned-int))

(defun session-auth-methods-list (session username)
	(with-foreign-string (fs-username username)
		(mapcar (lambda (item) (intern (string-upcase item) 'keyword))
						(split-sequence:split-sequence 
						 #\,
						 (--session-auth-methods-list 
							session fs-username (length username))))))

(defctype +ssh-agent+ :pointer)
(defcfun ("libssh2_agent_init" agent-init) +ssh-agent+
	(session +session+))

(defcfun ("libssh2_agent_free" agent-free) :void
	(agent +ssh-agent+))

(defcfun ("libssh2_agent_connect" agent-connect) +ERROR-CODE+
	(agent +ssh-agent+))

(defcfun ("libssh2_agent_disconnect" agent-disconnect) +ERROR-CODE+
	(agent +ssh-agent+))

(defcfun ("libssh2_agent_list_identities" agent-list-identies) +ERROR-CODE+
	(agent +ssh-agent+))

(defcenum +IDENTITY-AMOUNT+
	(:MORE 0)
	(:END  1))

(defcfun ("libssh2_agent_get_identity" --agent-get-identity) +IDENTITY-AMOUNT+
	(agent +ssh-agent+)
	(store :pointer) (previous-public-key :pointer))

(defun agent-identities-iterator (agent)
	(when (eq (agent-list-identies agent) :ERROR-NONE)
		(let ((agent agent)
					(prev  (null-pointer)))
			(lambda () 
				(with-foreign-object (store :pointer)
					(unless (eq (--agent-get-identity agent store prev)
											:END)
						(setf prev 
									(mem-aref store :pointer 0))))))))

(defmacro foreach-agent-identity ((identy agent) &body body)
	`(let ((agent ,agent)
				 (list-identies (agent-list-indenties ,agent))
				 (prev (null-pointer)))
		 (if (eq list-identies :ERROR-NONE)
				 (with-foreign-object (store :pointer)
					 (labels 
							 ((process-next-identity ()
									(unless (eq (--agent-get-identity agent store prev)
															:END)
										(let ((,identy (setf prev
																				 (mem-aref store :pointer 0))))
											,@body
											(process-next-identity)))))
						 (process-next-identity))))))													

(defctype +known-hosts+ :pointer)
(defcfun ("libssh2_knownhost_init" known-hosts-init) +known-hosts+
	(session +session+))

(defcfun ("libssh2_knownhost_free" known-hosts-free) :void
	(known-hosts +known-hosts+))

(defcfun ("libssh2_knownhost_readfile" --known-hosts-readfile) :int
	(known-hosts +known-hosts+) (filename :string) (type :int))

(defcfun ("libssh2_knownhost_writefile" --known-hosts-writefile) :int
	(known-hosts +known-hosts+) (filename :string) (type :int))

(defun known-hosts-readfile (hosts file)
	(with-foreign-string (foreign-file file)
		(let ((ret (--known-hosts-readfile hosts foreign-file 1)))
			(if (>= ret 0)
					(convert-from-foreign 0 '+ERROR-CODE+)
					(convert-from-foreign ret '+ERROR-CODE+)))))

(defun known-hosts-writefile (hosts file)
	(with-foreign-string (foreign-file file)
		(let ((ret (--known-hosts-writefile hosts foreign-file 1)))
			(if (>= ret 0)
					(convert-from-foreign 0 '+ERROR-CODE+)
					(convert-from-foreign ret '+ERROR-CODE+)))))

(defctype +key+ :pointer)
(defcfun ("libssh2_session_hostkey" --session-hostkey)  +key+
	(session +session+) (len :pointer) (type :pointer))

(defstruct key 
	(data 0 :read-only t)
	(size 0 :read-only t)
	(type 0 :read-only t))

(defun session-hostkey (session)
	(with-foreign-objects ((len :unsigned-int 1)
												(type :int 1))
		(let ((result (--session-hostkey session len type)))
			(make-key :data result 
								:size (mem-aref len :long 0)
								:type (mem-aref type :int 0)))))

(defcenum +HASH-TYPE+
	(:MD5  1)
	(:SHA1 2))

(defctype +keyhash+ :pointer)
(defcfun ("libssh2_hostkey_hash" session-hostkey-hash) +keyhash+
	(session +session+) (hash-type +HASH-TYPE+))

(defun session-hostkey-fingerprint (session &optional (type :SHA1))
	(let ((hash (session-hostkey-hash session type)))
		(format nil "~{~2,'0X~^:~}"
						(loop for i below (if (eq type :SHA1) 20 16)
							 collect (mem-aref hash :unsigned-char i)))))

(defbitfield +known-hosts-flags+ 
	(.type-plain. 1)
	(.type-sha1.  2)
	(.raw.        65536)
	(.base64.     131072)
	(.rsa1.       262144)
	(.ssh.        524288))

(defcenum +CHECK-VERDICT+ 
	(:FAILURE    3)
	(:NOT-FOUND  2)
	(:MISMATCH   1)
	(:MATCH      0))     

(defcstruct +known-host+
	(magic :unsigned-int)
	(node  :pointer)
	(name  :string)
	(key   :string)
	(type  +known-hosts-flags+))

(defcfun ("libssh2_knownhost_checkp" --known-hosts-checkp) +CHECK-VERDICT+
	(known-hosts +known-hosts+) (hostname :string) (port :int)
	(key +key+) (key-data-size :unsigned-int) 
	(type :int)  (known-host :pointer))

(defcfun ("libssh2_knownhost_check" --known-hosts-check) +CHECK-VERDICT+
	(known-hosts +known-hosts+) (hostname :string)
	(key +key+) (key-data-size :unsigned-int) 
	(type :int)  (known-host :pointer))

(defun known-hosts-check (known-hosts hostname key 
													&key
														(port nil)
														(flags '(.type-plain. .raw.))
														(known-host (null-pointer)))
	(let ((fp (key-data key)))
		(when (not (null-pointer-p fp))
			(with-foreign-string (-hostname hostname)
				(if port
						(--known-hosts-checkp known-hosts -hostname port 
															 fp
															 (key-size key)
															 (foreign-bitfield-value '+known-hosts-flags+ flags)
															 known-host)
						(--known-hosts-check known-hosts -hostname
																 fp
																 (key-size key)
																 (foreign-bitfield-value '+known-hosts-flags+ flags)
																 known-host))))))

(define-condition known-hosts-reading-error (ssh-generic-error)
	((file :type     string
				 :initarg  :file
				 :accessor file)))

(defmethod print-object :after ((khre known-hosts-reading-error) stream)
	(format stream "// ~a" (file khre)))

(defmacro with-known-hosts ( ( known-hosts (session known-hosts-filename)) &body body )
	`(let ((,known-hosts (known-hosts-init ,session)))
		 (unwind-protect
					(if (and (not (null-pointer-p ,known-hosts))
									 (eq (labels 
													 ((try-again ()
															(let ((result (known-hosts-readfile ,known-hosts ,known-hosts-filename)))
																(if (eq result :ERROR-FILE)
																		(restart-case 
																				(with-last-error (,session known-hosts-reading-error) 
																					:file ,known-hosts-filename)
																			(try-create-file ()
																				(unless
																						(eq (known-hosts-writefile ,known-hosts ,known-hosts-filename)
																								:ERROR-NONE)
																					(with-last-error (,session known-hosts-reading-error) 
																						:file ,known-hosts-filename))
																				(try-again))
																			(ignore () nil))
																		result))))
												 (try-again)) :ERROR-NONE))
							(progn
								,@body)
							(with-last-error (,session known-hosts-reading-error) 
								:file ,known-hosts-filename))
			 (unless (null-pointer-p ,known-hosts)
				 (known-hosts-free ,known-hosts)))))

(defcfun ("libssh2_knownhost_addc" --known-hosts-add) +ERROR-CODE+
	(known-hosts +known-hosts+) 
	(host :string) (salt :string) (key :pointer) (key-length :unsigned-int)
	(comment :string) (comment-length :unsigned-int)
	(typemask :int) (known-host +known-host+))

(defun known-hosts-add (known-hosts host-full-string key 
												&key 
													(comment "")
													(flags '(.type-plain. .raw. .ssh.))
													(salt  "")
													(store (null-pointer)))
	(if (and (not (null-pointer-p known-hosts))
					 (not (null-pointer-p (key-data key)))
					 (stringp host-full-string))
			(with-foreign-strings ((fs-host-full-string host-full-string)
														 (fs-salt    salt)
														 (fs-comment comment))
				(--known-hosts-add known-hosts 
													 fs-host-full-string fs-salt
													 (key-data key) (key-size key)
													 fs-comment (length comment)
													 (foreign-bitfield-value '+known-hosts-flags+ flags)
													 store))))
													 
(defcfun ("libssh2_agent_userauth" --agent-userauth) +ERROR-CODE+
	(agent +ssh-agent+) (username :string) (identity :pointer))

(defun user-auth-agent (agent username identity)
	(with-foreign-string (fs-username username)
		(--agent-userauth agent fs-username identity)))

(defcfun ("libssh2_userauth_password_ex" --user-auth-password) +ERROR-CODE+
	(session +session+) 
	(username :string) (username-length :unsigned-int)
	(password :string) (password-length :unsigned-int)
	(password-change :pointer))
			
(defun user-auth-password (session username password &optional (callback (null-pointer)))
	(let ((username-length (length username))
				(password-length (length password)))
		(with-foreign-strings ((fs-username username)
													 (fs-password password))
			(--user-auth-password session
														fs-username username-length
														fs-password password-length
														callback))))

(defctype +channel+ :pointer)
(defcfun ("libssh2_channel_open_ex" --channel-open-ex) +channel+
	(session +session+) (channel-type :string) (channel-type-length :unsigned-int)
	(window-size :unsigned-int) (packet-size :unsigned-int) 
	(message :string) (message-length :unsigned-int))
					
(defun channel-open (session &key (channel-type "session")
															 (window-size 262144)
															 (packet-size 32768)
															 (message ""))
	(with-foreign-strings ((fs-channel-type channel-type)
												 (fs-message      message))
		(let* ((message-length (length message))
					 (new-channel 
						(--channel-open-ex session 
															 fs-channel-type (length channel-type)
															 window-size packet-size 
															 (if (> message-length 0)
																	 fs-message
																	 (null-pointer)) message-length)))
			(if (null-pointer-p new-channel)
					(session-last-errno session)
					new-channel))))
					

(defcfun ("libssh2_channel_close" channel-close) +ERROR-CODE+
	(channel +channel+))

(defcfun ("libssh2_channel_free" channel-free) +ERROR-CODE+
	(channel +channel+))

(defcfun ("libssh2_channel_wait_closed" channel-wait-closed) +ERROR-CODE+
	(channel +channel+))

(defcfun ("libssh2_channel_process_startup" --channel-process-startup) +ERROR-CODE+
	(channel +channel+) 
	(request :string) (request-length :unsigned-int)
	(message :string) (message-length :unsigned-int))

(defcfun ("libssh2_channel_setenv_ex" --channel-setenv-ex) +ERROR-CODE+
	(channel +channel+) 
	(varname :string) (varname-len :int)
	(value :string) (value-len :int))

(defun channel-setenv (channel name value)
	(with-foreign-strings ((fs-name  name)
												 (fs-value value))
		(--channel-setenv-ex channel 
												 fs-name  (length name)
												 fs-value (length value))))

(defun channel-process-start (channel request message)
	(with-foreign-strings ((fs-request request)
												 (fs-message message))
		(--channel-process-startup channel 
															 fs-request (length request)
															 fs-message (length message))))


(defun channel-exec (channel cmd)
	(channel-process-start channel "exec" cmd))

(defun channel-shell (channel cmd)
	(channel-process-start channel "shell" cmd))

(defun channel-subsysten (channel cmd)
	(channel-process-start channel "subsystem" cmd))

;; ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, size_t buflen); 
(defcenum +STREAM-ID+
	(:STDOUT   0)
	(:STDERR   1)
	(:EXTENDED -1)
	(:ALL      -2))

(defcfun ("libssh2_channel_read_ex" --channel-read-ex) :int
	(channel +CHANNEL+) (stream +STREAM-ID+)
	(buffer :pointer) (buffer-length :unsigned-int))

(defcfun ("libssh2_channel_flush_ex" --channel-flush-ex) :int
	(channel +CHANNEL+) (stream +STREAM-ID+))

(defun channel-flush (channel)
	(let ((ret (--channel-flush-ex channel :ALL)))
		(if (> ret 0)
				:ERROR-NONE
				(convert-from-foreign ret '+ERROR-CODE+))))

(defun channel-read (channel output-buffer &key (start 0) (end nil) (type :STDOUT))
	(with-pointer-to-vector-data (buffer output-buffer)
		(let ((ret (--channel-read-ex channel type
																	(inc-pointer buffer start) 
																	(if end 
																			(- (min end (length output-buffer))
																				 start)
																			(- (length output-buffer)
																				 start)))))
			(values-list 
			 (if (>= ret 0)
					 (list
						ret
						(convert-from-foreign 0 '+ERROR-CODE+))
					 (list
						0
						(convert-from-foreign ret '+ERROR-CODE+)))))))

(defcfun ("libssh2_channel_write_ex" --channel-write-ex) :int
	(channel +CHANNEL+) (stream +STREAM-ID+)
	(buffer :pointer) (buffer-length :unsigned-int))

(defmacro channel-write-with-conv (name conv)
	`(defun ,name (channel data &key (start 0) (end nil) (type :STDOUT))
		 (,conv (buffer data)
						(let ((ret (--channel-write-ex channel type
																					 (inc-pointer buffer start)
																					 (if end
																							 (- (min end (length data))
																									start)
																							 (- (length data)
																									start)))))
							(values-list
							 (if (> ret 0)
									 (list 
										ret
										(convert-from-foreign 0 '+ERROR-CODE+))
									 (list
										0
										(convert-from-foreign ret '+ERROR-CODE+))))))))

(channel-write-with-conv channel-write with-pointer-to-vector-data)
(channel-write-with-conv channel-write-string with-foreign-string)

(defcfun ("libssh2_channel_send_eof" channel-send-eof) +ERROR-CODE+
	(channel +channel+))

(defcfun ("libssh2_channel_get_exit_status" channel-exit-status) :int
	(channel +channel+))

;; (defcfun ("libssh2_channel_get_exit_signal" --channel-exit-signal) +ERROR-CODE+
;; 	(channel +channel+) 


;; CLOS FACADE: FOR BLOCKING STREAMS!! ;;
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
	
(define-condition ssh-handshake-error (ssh-generic-error) ())

(define-condition ssh-bad-hostkey (error)
	((reason :type      +CHECK-VERDICT+
					 :accessor  reason
					 :initarg   :reason)
	 (hash   :type      string
					 :accessor  hash
					 :initarg   :hash)))

(defmethod create-ssh-connection (host port (hosts-db string))
	(let ((new-session nil)
				(new-socket  nil)
				(retval      :ERROR-NONE))
		(unwind-protect 
				 (progn
					 (setq new-session (session-init))
					 (setq new-socket (usocket:socket-connect host port))
					 
					 (setq retval 
								 (repeat-and-wait-until-complete (new-socket)
									 (session-handshake new-session (usocket-get-fd new-socket))))
					 
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
			 (repeat-and-wait-until-complete ((socket ssh))
				 (session-disconnect (session ssh) 
														 :description description
														 :lang   lang))
		(progn
				(session-free (session ssh)))))

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

(defmethod authentication :around ((ssh ssh-connection) (auth auth-data))
	(if (auth-passed ssh)
			t
			(if (ssh-verify-session ssh)
					(setf (auth-passed ssh)
								(call-next-method)))))

(defmethod authentication ((ssh ssh-connection) (auth auth-password))
	(repeat-and-wait-until-complete ((socket (session ssh)))
		(user-auth-password (session  ssh)
												(login    auth)
												(password auth))))

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
														 (repeat-and-wait-until-complete ((socket ssh))
															 (--agent-userauth agent fs-username identity))
														 :ERROR-NONE)
														(return t))))))
						 (throw-last-error (session ssh)))
			(when agent 
				(agent-free agent)))))

(defvar *ssh-channel-buffer-size* 64)

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
				 (let ((amount (repeat-and-wait-until-complete ((socket stream))
												 (channel-read (channel stream) 
																			 (input-buffer stream)))))
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
								 (repeat-and-wait-until-complete ((socket stream))
									 (channel-read (channel stream)
																 (input-buffer stream))))
								 
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
		(repeat-and-wait-until-complete ((socket stream))
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
				(repeat-not-wait)))))


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
					 (repeat-and-wait-until-complete (socket)
						 (channel-write channel
														output-buffer
														:start output-pos
														:end   output-size))))
			
			(incf output-pos amount)
			(if (= output-pos
						 output-size)
					(setf output-pos  0
								output-size 0 ))
			(if dont-send-eof
					amount
					(repeat-and-wait-until-complete (socket)
						(channel-send-eof channel))))))

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
	(repeat-and-wait-until-complete ((socket stream))
		(channel-write-string (channel stream) 
													sharable-sequence
													:start start
													:end   end)))

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
	(let ((socket  (socket stream))
				(channel (channel stream)))
		(when (not (null-pointer-p channel))
			(unless abort
				(stream-force-output stream)
				(repeat-and-wait-until-complete (socket)
					(channel-flush channel)))
			
			(repeat-and-wait-until-complete (socket)
				(channel-close channel))
			(channel-free channel))))

(defmethod execute ((ssh ssh-connection) (command string))
	(with-slots (socket session) ssh
		(let ((new-channel 
					 (repeat-and-wait-until-complete (socket)
						 (channel-open session))))
			(if (pointerp new-channel)
					(if (not (null-pointer-p new-channel))
							(let ((retval (repeat-and-wait-until-complete (socket)
															(channel-exec new-channel command))))
								(if (eq retval :ERROR-NONE)
										(make-instance 'ssh-channel-stream
																	 :socket  socket
																	 :channel new-channel)
										(throw-last-error session)))
							(throw-last-error session))
					(throw-last-error session)))))

(defmacro with-execute ((stdio-stream ssh-connection command)
												&body body)
	`(let ((,stdio-stream (execute ,ssh-connection ,command)))
		 (unwind-protect
					(let ((body-retval
								 (progn ,@body)))
						(values-list 
						 (list body-retval
									 (channel-exit-status (channel ,stdio-stream)))))
			 (close ,stdio-stream))))

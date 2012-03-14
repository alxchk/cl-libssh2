;; -*- mode: lisp; tab-width: 4; ident-tabs-mode: nil -*-

(in-package :libssh2)

(include "sys/types.h" "sys/stat.h")
(cstruct +stat+   "struct stat"
				 (dev     "st_dev"     :type :unsigned-int)
				 (ino     "st_ino"     :type :unsigned-int)
				 (mode    "st_mode"    :type :unsigned-int)
				 (nlink   "st_nlink"   :type :unsigned-int)
				 (uid     "st_uid"     :type :unsigned-int)
				 (gid     "st_gid"     :type :unsigned-int)
				 (rdev    "st_rdev"    :type :unsigned-int)
				 (size    "st_size"    :type :unsigned-int)
				 (atime   "st_atime"   :type :unsigned-int)
				 (mtime   "st_mtime"   :type :unsigned-int)
				 (ctime   "st_ctime"   :type :unsigned-int))


				 

(ql:quickload :ironclad)

(defun random-string (n)
  (map 'string #'code-char (ironclad:random-data n)))

(defun str->bytes (keystr)
  (map '(vector (unsigned-byte 8)) #'char-code keystr))

(defun alloc-byte-vector (&optional (len 16))
  (make-array len :element-type '(unsigned-byte 8)))

(defun vector-xor (lv rv)
  (let ((new-vec (alloc-byte-vector 16)))
    (do ((i 0 (1+ i)))
      ((= i 16) new-vec)
      (setf (aref new-vec i)
            (logxor (aref lv i)
                    (aref rv i))))))

(defun ecb (keystr)
  (ironclad:make-cipher :AES
                        :key (str->bytes keystr)
                        :mode :ECB))

(defun pkcs-7 (plaintext block-size)
  (let ((n (- block-size
              (mod (length plaintext) block-size))))
    (concatenate 'string
                 plaintext
                 (format nil "~v@{~A~:*~}" n (code-char n)))))

(defun aes-cbc-encrypt (key plaintext iv)
  (let* ((str-bytes (str->bytes (pkcs-7 plaintext 16)))
         (cipher (ecb key))
         (n (/ (length str-bytes) 16))
         (acc)
         (prev iv))
    (do ((i 0 (1+ i)))
      ((= i n) (map 'string #'code-char acc))
      (let* ((slice (subseq str-bytes (* i 16) ( * (1+ i) 16)))
             (bytes (vector-xor prev slice)))
        (ironclad:encrypt-in-place cipher bytes)
        (setf acc (concatenate 'vector acc bytes)
              prev bytes)))))

(defun aes-ecb-encrypt (key str)
  (let ((str-bytes (str->bytes str))
        (cipher (ecb key)))
    (ironclad:encrypt-in-place cipher str-bytes)
    (map 'string #'code-char str-bytes)))

(defmacro randomly (then else)
  `(if (zerop (random 2))
     ,then
     ,else))

;; contrived service we're attacking:
(defun encryption-oracle (input)
  (let ((input (concatenate 'string
                            (random-string (+ 5 (random 5)))
                            input
                            (random-string (+ 5 (random 5)))))
        (key (random-string 16)))
    (randomly
      (aes-cbc-encrypt key input (ironclad:random-data 16))
      (aes-ecb-encrypt key (pkcs-7 input 16)))))

;; our attacking code:
(let ((seen (make-hash-table :test #'equal)))
  (defun seen? (str)
    (prog1
      (gethash str seen)
      (setf (gethash str seen) t)))

  (defun duplicate-blocks? (str &optional (block-size 16))
    (let ((num-blocks (/ (length str) block-size)))
      (do ((i 0 (1+ i)))
        ((= i num-blocks) nil)
        (let ((block-n (subseq str
                               (* i block-size)
                               (* (1+ i) block-size))))
          (when (seen? block-n)
            (return-from duplicate-blocks? t)))))))


;; test it a few times
(let ((payload (format nil "~v@{~A~:*~}" 48 "A")))
  (do ((i 0 (1+ i)))
    ((= i 10))
    (if (duplicate-blocks? (encryption-oracle payload))
      (format t "ECB detected!~%")
      (format t "...not ECB...~%"))))

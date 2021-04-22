(ql:quickload :ironclad)
(ql:quickload :cl-base64)

(defun pkcs-7 (plaintext block-size)
  (let ((n (- block-size
              (mod (length plaintext) block-size))))
    (concatenate 'string
                 plaintext
                 (format nil "~v@{~A~:*~}" n (code-char n)))))

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
  (ironclad:make-cipher :AES :key (str->bytes keystr) :mode :ECB))

;; TODO: swap `encrypt-in-place` for `encrypt`
(defun aes-cbc-encrypt (key plaintext &optional (iv (alloc-byte-vector)))
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

;; meh...a little ugly, but ok
(defun aes-cbc-decrypt (key plaintext &optional (iv (alloc-byte-vector)))
  (let* ((str-bytes (str->bytes plaintext))
         (cipher (ecb key))
         (n (/ (length str-bytes) 16))
         (acc)
         (prev iv))
    (do ((i 0 (1+ i)))
        ((= i n) (map 'string #'code-char acc))
      (let ((ciphertext-block (subseq str-bytes (* i 16) ( * (1+ i) 16)))
            (plaintext-block (alloc-byte-vector)))
        (ironclad:decrypt cipher ciphertext-block plaintext-block)
        (let ((plaintext-block (vector-xor prev plaintext-block)))
          (setf acc (concatenate 'vector acc plaintext-block)
                prev ciphertext-block))))))

(with-open-file (instream "10.txt")
  (let ((c1 (cl-base64:base64-stream-to-string instream)))
    (format t "~a" (aes-cbc-decrypt "YELLOW SUBMARINE" c1))))

;; > "I'm back and I'm ringin' the bell"...

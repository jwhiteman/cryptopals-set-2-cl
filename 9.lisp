(defun pkcs-7 (plaintext block-size)
  (let ((n (- block-size
              (mod (length plaintext) block-size))))
    (concatenate 'string
                 plaintext
                 (format nil "~v@{~A~:*~}" n (code-char n)))))

;; test...
(format t "~A~%" (pkcs-7 "YELLOW SUBMARINE" 20))
(format t "~A~%" (pkcs-7 "YELLOW SUBMARINE" 8))
(format t "~A~%" (pkcs-7 "YELLOW SUBMARINES" 8))
(format t "~A~%" (pkcs-7 "Y" 16))

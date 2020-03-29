package cipher

type Block interface{
    BlockSize() int
    Encrypt(dst, src []byte)
    Decrypt(dst, src []byte)
}

type BlockMode interface {
	BlockSize() int

	CryptBlocks(dst, src []byte)
}

func dup(p []byte) []byte{
    q := make([]byte, len(p))
    copy(q, p)
    return q
}

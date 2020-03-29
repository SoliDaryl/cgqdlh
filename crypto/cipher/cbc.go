package cipher

type cbc struct {
    b       Block
    blockSize int
    iv      []byte
    tmp     []byte
}

type cbcEncrypter cbc

type cbcDecrypter cbc

func newCBC(b Block, iv []byte) *cbc {
    return &cbc{
        b:b,
        blockSize: b.BlockSize(),
        iv: dup(iv),
        tmp: make([]byte, b.BlockSize()),
    }
}

type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) BlockMode
}

func NewCBCEncrypter(b Block, iv []byte) BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cipher.NewCBCEncrypter: iv 的长度与分组长度不同")
    }

    if cbc, ok := b.(cbcEncAble); ok {
        return cbc.NewCBCEncrypter(iv)
    }

	return (*cbcEncrypter)(newCBC(b, iv))
}

func (c *cbcEncrypter) BlockSize() int{
    return c.blockSize
}

func (c *cbcEncrypter) CryptBlocks(dst, src []byte){
    if len(src)%c.blockSize != 0 {
        panic("crypto/cipher: 输入的分组不完整!")
    }

    if len(dst) < len(src) {
        panic("crypot/cipher: 输出空间比输入空间小!")
    }

    if len(src) == 0{
        return
    }

    end := len(src)
    start := end - c.blockSize
}

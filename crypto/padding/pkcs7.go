package padding

import (
    "crypto/cipher"
    "strconv"
)

type SuffixSizeError int

func (d SuffixSizeError) Error() string {
    return "需要截取的长度:" + strconv.Itoa(int(d)) + ", 不服和条件"
}

func AddPKCS7(c cipher.Block, data []byte) (out []byte){
    l := len(data) % c.BlockSize()
    var suffix []byte
    if l == 0 {
        l = c.BlockSize()
        suffix = make([]byte, l)
    } else {
        l = c.BlockSize() - l
        suffix = make([]byte, l)
    }

    value := byte(l)
    for index, _ := range suffix {
        suffix[index] = value
    }

    out = append(data, suffix...)
    return
}

func RemovePKCS7(c cipher.Block, data []byte) (out []byte, err error){
    l := int(data[len(data)-1])
    if l > c.BlockSize() {
        return nil, SuffixSizeError(l)
    }

    out = data[:len(data) - 1 - l]
    return out, nil
}

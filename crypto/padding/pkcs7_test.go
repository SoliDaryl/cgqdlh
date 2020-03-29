package padding

import (
    "fmt"
    "testing"
)

type testCipher struct{
    length int
}

func (c *testCipher) BlockSize() int{
    return c.length
}

func (c *testCipher) Encrypt(dst, src []byte){}

func (c *testCipher) Decrypt(dst, src []byte){}

func TestAddPKCS7(t *testing.T) {
    data := []byte {
        0x1, 0x2, 0x3,
    }
    result := []byte{
        0x1, 0x2, 0x3, 0x3, 0x3, 0x3,
    }
    c := testCipher{6}
    data = AddPKCS7(c, data)
    fmt.Println(data)
    for index, n := range result {
        if n != data[index]{
            t.Error(`data != result`)
            return
        }
    }
}

func TestRemovePKCS7(t *testing.T) {
    data := []byte{
        0x1, 0x2, 0x3, 0x3, 0x3, 0x3,
    }
    result := []byte {
        0x1, 0x2, 0x3,
    }
    data, _ = RemovePKCS7(new(testCipher{6}), data)
    fmt.Println(data)
    for index, n := range result {
        if n != data[index]{
            t.Error(`data != result`)
            return
        }
    }
}

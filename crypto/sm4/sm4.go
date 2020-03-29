package sm4

import(
    "crypto/cipher"
    "encoding/binary"
    "strconv"
)

type KeySizeError int

const BlockSize = 16

func (k KeySizeError) Error() string {
    return "crypto/sm4: invalid key size " + strconv.Itoa(int(k))
}

type sm4Cipher struct{
    subkeys [32]uint32
}

func NewCipher(key []byte) (cipher.Block, error){
    if len(key) != 16 {
        return nil, KeySizeError(len(key))
    }
    c := new(sm4Cipher)
    c.generateSubkeys(key)
    return c, nil
}

func (c *sm4Cipher) BlockSize() int{
    return BlockSize
}

func (c *sm4Cipher) Encrypt(dst, src []byte){
    if len(src) < c.BlockSize() {
        panic("输入不足一个分组长度")
    }

    if len(dst) < c.BlockSize() {
        panic("输出不足一个分组长度")
    }
    encryptBlock(c.subkeys[:], dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte){
    if len(src) < c.BlockSize() {
        panic("输入不足一个分组长度")
    }

    if len(dst) < c.BlockSize() {
        panic("输出不足一个分组长度")
    }
    decryptBlock(c.subkeys[:], dst, src)
}

func encryptBlock(subkeys []uint32, dst, src []byte){
    cryptBlock(subkeys, dst, src, false)
}

func decryptBlock(subkeys []uint32, dst, src []byte){
    cryptBlock(subkeys, dst, src, true)
}

func cryptBlock(subkeys []uint32, dst, src []byte, decrypt bool){
    tmp := src
    if decrypt {
        for i := 0; i < 32; i++ {
            tmp = feistel(tmp, subkeys[31 - i])
        }
    } else {
        for i := 0; i < 32; i++ {
            tmp = feistel(tmp, subkeys[i])
        }
    }
    tmp = reverseOrder(tmp)
    copy(dst, tmp)
}

// f 圈函数
// 输入明文 128bit, 输出 128bit
// out = f(in) = X[i+0] ^ t(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk, (X[i+0], X[i+1], X[i+2], X[i+3]) = in
func feistel(in []byte, rk uint32) []byte {
    var (
        xp0 = binary.BigEndian.Uint32(in[:4])
        xp1 = binary.BigEndian.Uint32(in[4:8])
        xp2 = binary.BigEndian.Uint32(in[8:12])
        xp3 = binary.BigEndian.Uint32(in[12:16])
    )
    tOut := make([]byte, 4, 4)
    binary.BigEndian.PutUint32(tOut, xp0 ^ t(xp1 ^ xp2 ^ xp3 ^ rk))
    out := make([]byte, 16, 16)

    copy(out[:4], in[4:8])
    copy(out[4:8], in[8:12])
    copy(out[8:12], in[12:16])
    copy(out[12:16], tOut[:])
    return out
}

func reverseOrder(last []byte) []byte{
    out := make([]byte, BlockSize, BlockSize)
    copy(out[:4], last[12:16])
    copy(out[4:8], last[8:12])
    copy(out[8:12], last[4:8])
    copy(out[12:16], last[:4])
    return out
}

// t 函数
// 是一个可逆变换, 由非线性变换 tau 和线性变换 l 复合而成
func t(in uint32) (out uint32){
    out = l(tau(in))
    return
}

// l 函数
// 输入 32bit, 输出 32bit
// 非线性变换 tau 的输出为 L 函数的输入
// c = l(b) = b ^ (b<<<2) ^ (b<<<10) ^ (b<<<18) ^ (b<<<24), <<< 代表循环左移
func l(b uint32) (c uint32){
    tmp1 := (b<<2) | (b >> 30 & (1<<2-1))
    tmp2 := (b<<10) | (b >> 22 & (1<<10-1))
    tmp3 := (b<<18) | (b >> 14 & (1<<18-1))
    tmp4 := (b<<24) | (b >> 8 & (1<<24-1))
    c = b^(tmp1)^(tmp2)^(tmp3)^(tmp4)
    return
}

// τ函数
// 非线性变换, 由4个并行的S盒构成
// 输入 32bit 输出32bit
func tau(a uint32)(b uint32){
    bytes := make([]byte, 4, 4)
    binary.BigEndian.PutUint32(bytes, a)
    bytes[0] = sBoxFunc(bytes[0])
    bytes[1] = sBoxFunc(bytes[1])
    bytes[2] = sBoxFunc(bytes[2])
    bytes[3] = sBoxFunc(bytes[3])
    b = binary.BigEndian.Uint32(bytes)
    return
}

func sBoxFunc(in byte) (out byte){
    left, right := (in >> 4) & (1 << 4 -1), in & (1 << 4 -1)
    out = sBox[left][right]
    return
}

// 生成圈密钥
// mk = (mk0, mk1, mk2, mk3), (k0, k1, k2, k3) = (mk0^fk0, mk1^fk1, mk2^fk2, mk3^fk3)
// rk[i] = k[i+4] = k[i] ^ t1(k[i+1] ^ k[i+2] ^ k[i+3] ^ ck[i])
func (c *sm4Cipher) generateSubkeys(mk []byte){
    var (
        mk0 = binary.BigEndian.Uint32(mk[:4])
        mk1 = binary.BigEndian.Uint32(mk[4:8])
        mk2 = binary.BigEndian.Uint32(mk[8:12])
        mk3 = binary.BigEndian.Uint32(mk[12:16])
    )
    kp0, kp1, kp2, kp3 := mk0 ^ fk[0], mk1 ^ fk[1], mk2 ^ fk[2], mk3 ^ fk[3]
    for i := 0; i < 32; i++ {
        c.subkeys[i] = kp0 ^ t1(kp1 ^ kp2 ^ kp3 ^ ck[i])
        kp0, kp1, kp2, kp3 = kp1, kp2, kp3, c.subkeys[i]
    }
}

// t1 函数
// 与 t 函数类似, 只是 l 函数换位 l1 函数
// 是一个可逆变换, 由非线性变换 tau 和线性变换 l1 符合而成
func t1(in uint32) (out uint32){
    out = l1(tau(in))
    return
}

// l1 函数
// 输入 32bit, 输出 32bit
// 非线性变换 tau 的输出为 l1 函数的输入
// c = l1(b) = b ^ (b<<<13) ^ (b<<<23), <<< 代表循环左移
func l1(b uint32) (c uint32){
    tmp1 := (b<<13) | (b >> 19 & (1<<13-1))
    tmp2 := (b<<23) | (b >> 9 & (1<<23-1))
    c = b ^ (tmp1) ^ (tmp2)
    return
}

package des

import (
    "fmt"
    "encoding/binary"
)

func Test(){
    fmt.Println("des test...")
}

// 创建密码器
func CreateCipher(key []byte) *desCipher {
    if len(key) != BlockSize {
        panic("key lenght not is 8")
    }
    c := new(desCipher)
    c.genKey(key)
    return c
}

const BlockSize = 8

type desCipher struct{
    subkeys [16]uint64
}

// 加密
func (c *desCipher) Encode(dst, src []byte) {
    if len(src) < c.BlockSize() {
        panic("输入不足一个分组长度")
    }

    if len(dst) < c.BlockSize() {
        panic("输出不足一个分组长度")
    }
    cryptBlock(c.subkeys, dst, src, false)
}

// 解密
func (c *desCipher) Descode(dst, src []byte){
    if len(src) < c.BlockSize() {
        panic("输入不足一个分组长度")
    }

    if len(dst) < c.BlockSize() {
        panic("输出不足一个分组长度")
    }
    cryptBlock(c.subkeys, dst, src, true)
}

// 分组长度
func (c *desCipher) BlockSize() int {
    return BlockSize
}

// 加密/解密组
func cryptBlock(subkeys [16] uint64, dst, src []byte, decrypt bool){
    block := permutedInitialBlock(binary.BigEndian.Uint64(src[:]))
    left, right := uint32(block >> 32), uint32(block)
    if decrypt {
        for i := len(subkeys) - 1; i >= 0; i-- {
            left, right = feistel(left, right, subkeys[i])
        }
    } else {
        for _,n := range subkeys {
            left, right = feistel(left, right, n)
        }
    }
    left, right = right, left
    block = uint64(left) << 32 | uint64(right)
    block = permutedFinalBlock(block)
    binary.BigEndian.PutUint64(dst, block)
}

// 生成密钥
func (c *desCipher) genKey(keyBytes []byte) {
    keyInt := binary.BigEndian.Uint64(keyBytes[:])
    keyInt = pc1(keyInt)
    left, right := rotateKeys(keyInt)
    for i := 0; i < 16; i++ {
        c.subkeys[i] = pc2(uint64(left[i]) << 28 | uint64(right[i]))
    }
}

// 密钥初始置换 PC-1
func pc1(key uint64) (block uint64){
    var bit uint64
    for index, n := range permutedChoice1 {
        bit = (key >> (n - 1)) & 1
        block |= bit << uint(56 - 1 - index)
    }
    return
}

// 循环位移
// 将16个圈子密钥循环移位的结果一次计算出
func rotateKeys(key uint64) (left [16]uint32, right [16]uint32) {
    leftRotate := uint32(key >> 28)
    rightRotate := uint32(key) << 4 >> 4
    for i := 0; i < 16; i++ {
        l := leftRotate << (4 + ksRotations[i]) >> 4
        r := leftRotate >> uint32(28 - i)
        left[i] = l | r
        leftRotate = left[i]

        l = rightRotate << (4 + ksRotations[i]) >> 4
        r = rightRotate >> uint32(28 - i)
        right[i] = l | r
        rightRotate = right[i]
    }
    return
}

// 轮密钥置换PC-2
func pc2(in uint64) (out uint64) {
    var bit uint64
    for index, n := range permutedChoice2 {
        bit = (in >> (n -1)) & 1
        out |= bit << uint64(48 - 1 - index)
    }
    return
}

// 初始置换IP
func permutedInitialBlock(block uint64) (out uint64) {
    var bit uint64
    for index, n := range initialPermutation {
        bit = block >> (n -1) & 1
        out |= bit << uint64(64 - 1 - index)
    }
    return
}

// 逆初始置换IP^-1
func permutedFinalBlock(block uint64) (out uint64){
    var bit uint64
    for index, n := range finalPermutation {
        bit = block >> (n -1) & 1
        out |= bit << uint64(64 - 1 - index)
    }
    return
}

// 圈函数
func feistel(left, right uint32, subkey uint64) (lout, rout uint32){
    lout = right
    rout = left ^ f(right, subkey)
    return
}

// 圈函数中的 f 函数
func f(in uint32, subkey uint64) (out uint32) {
    var (
        bit, eResult uint64
        sResult uint32
    )

    // 进行E盒扩充, 输入32位,输出48位
    for index, n := range expansionFunction {
        bit = uint64(in) >> (n -1) & 1
        eResult |= bit << uint64(48 - 1 - index)
    }
    // E盒扩展的结果与圈子密钥XOR操作
    eResult ^= subkey

    // 将扩充后的函数分为8个组, 每个组6个bit, 进行S盒变换
    for i := 0; i < 8; i++ {
        // 获取组
        bit = eResult >> uint64(6*(8 - 1 - i)) & (1 << 6 -1)
        // 查S盒表
        y := (bit >> (6 -1) & 1 << 1) | (bit & 1)
        x := (bit >> 1) & (1 << 4 - 1)
        sResult |= uint32(sBoxes[i][y][x]) << uint32(4*(8 - 1 - i))
    }

    // p盒置换
    var b uint32
    for index, n := range permutationFunction {
        b = sResult >> (n - 1) & 1
        out |= b << uint32(32 - 1 - index)
    }
    return
}



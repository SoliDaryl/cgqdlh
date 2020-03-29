package io

import(
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestOsIoutil(t *testing.T){
    from := "/home/solidaryl/goio.txt"
    target := "/home/solidaryl/tgoio.txt"
    err := CpFile(target, from)

    assert.Nil(t, err)
}

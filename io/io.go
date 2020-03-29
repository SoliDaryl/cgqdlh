package io

import (
  "fmt"
  "io/ioutil"
  "os"
)

func CpFile(target, from string) error {
  fileObj, err := os.Open(from)
  if err != nil {
    return err
  }
  defer fileObj.Close()

  contents, err := ioutil.ReadAll(fileObj)
  if err != nil {
    return err
  }
  file, err := os.Create(target)
  if err != nil {
    return err
  }
  n, err := file.Write(contents)
  if err != nil {
    return nil
  }
  fmt.Printf("num:%d\n", n)
  return nil
}

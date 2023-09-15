package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"
    "golang.org/x/crypto/pbkdf2"
)

func main() {
    // Solicitar uma senha ao usuário
    fmt.Print("Digite a senha: ")
    var password string
    _, err := fmt.Scanln(&password)
    if err != nil {
        fmt.Println("Erro ao ler a senha:", err)
        return
    }

    // Pasta contendo os arquivos a serem criptografados
    folderPath := "./data"
    encodePath := "./encoded"

    // Derivar uma chave de criptografia a partir da senha
    key := deriveKeyFromPassword(password)

    // Criar a pasta de destino para os arquivos criptografados, se ainda não existir
    if err := os.MkdirAll(encodePath, 0755); err != nil {
        fmt.Println("Erro ao criar a pasta de destino:", err)
        return
    }

    // Começar a criptografia recursiva
    if err := encryptDirectory(key, folderPath, encodePath); err != nil {
        fmt.Println("Erro ao criptografar a pasta:", err)
    } else {
        fmt.Println("Criptografia concluída com sucesso.")
    }

    // if err := removeEmptyDirectories(folderPath); err != nil {
    //     fmt.Println("Erro ao remover pastas vazias:", err)
    //     return
    // }

    fmt.Println("Pastas vazias removidas com sucesso.")
}

// Função para derivar uma chave de criptografia a partir de uma senha
func deriveKeyFromPassword(password string) []byte {
    salt := []byte("31b8cfb3-1600-4c5f-9aa8-de150c17cb30")

    // Use PBKDF2 para derivar a chave
    key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
    return key
}

// Função para criptografar um arquivo
// func encryptFile(key []byte, inputFile, outputFile string) error {
//     plaintext, err := os.ReadFile(inputFile)
//     if err != nil {
//         return err
//     }

//     block, err := aes.NewCipher(key)
//     if err != nil {
//         return err
//     }

//     ciphertext := make([]byte, aes.BlockSize+len(plaintext))
//     iv := ciphertext[:aes.BlockSize]
//     if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//         return err
//     }

//     stream := cipher.NewCFBEncrypter(block, iv)
//     stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

//     return os.WriteFile(outputFile, ciphertext, 0644)
// }

func encryptFile(key []byte, inputFile, outputFile string) error {
    plaintext, err := os.ReadFile(inputFile)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    if err := os.WriteFile(outputFile, ciphertext, 0644); err != nil {
        return err
    }

    // Remova o arquivo original após a criptografia
    if err := os.Remove(inputFile); err != nil {
        return err
    }


    return nil
}

func removeEmptyDirectories(directoryPath string) error {
    entries, err := ioutil.ReadDir(directoryPath)
    if err != nil {
        return err
    }

    for _, entry := range entries {
        fullPath := filepath.Join(directoryPath, entry.Name())

        if entry.IsDir() {
            // Recursivamente, remova pastas vazias dentro desta pasta
            if err := removeEmptyDirectories(fullPath); err != nil {
                return err
            }

            // Após a recursão, tente remover a pasta atual se estiver vazia
            if err := os.RemoveAll(fullPath); err != nil {
                return err
            }
        }
    }

    // Após percorrer todas as entradas, tente remover o próprio diretório se estiver vazio
    if err := os.RemoveAll(directoryPath); err != nil {
        return err
    }



    return nil
}

// Função recursiva para criptografar uma pasta e seus subdiretórios
func encryptDirectory(key []byte, sourceDir, destDir string) error {
    return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        relPath, _ := filepath.Rel(sourceDir, path)
        destPath := filepath.Join(destDir, relPath)

        if info.IsDir() {
            // Crie a pasta de destino, se ainda não existir
            if err := os.MkdirAll(destPath, 0755); err != nil {
                return err
            }
        } else {
            // Criptografe o arquivo
            if err := encryptFile(key, path, destPath+".enc"); err != nil {
                return err
            }
        }

        return nil
    })
}

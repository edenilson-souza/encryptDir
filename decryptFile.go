package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "fmt"
    "os"
    "path/filepath"
    "strings"
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
    folderPath := "./encoded"
    encodePath := "./data"

    // Derivar uma chave de criptografia a partir da senha
    key := deriveKeyFromPassword(password)

    // Criar a pasta de destino para os arquivos criptografados, se ainda não existir
    if err := os.MkdirAll(encodePath, 0755); err != nil {
        fmt.Println("Erro ao criar a pasta de destino:", err)
        return
    }

    // Começar a criptografia recursiva
    if err := decryptDirectory(key, folderPath, encodePath); err != nil {
        fmt.Println("Erro ao criptografar a pasta:", err)
    } else {
        fmt.Println("Descriptografia concluída com sucesso.")
    }
}

// Função para derivar uma chave de criptografia a partir de uma senha
func deriveKeyFromPassword(password string) []byte {
    salt := []byte("31b8cfb3-1600-4c5f-9aa8-de150c17cb30")

    // Use PBKDF2 para derivar a chave
    key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
    return key
}

// Função para descriptografar um arquivo
func decryptFile(key []byte, inputFile, outputFile string) error {
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return fmt.Errorf("arquivo criptografado inválido")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

    // Remova a extensão .enc do nome do arquivo de saída
    outputFile = strings.TrimSuffix(outputFile, ".enc")

	if err := os.WriteFile(outputFile, ciphertext, 0644); err != nil {
        return err
    }

    // // Remova o arquivo original após a descriptografia
    // if err := os.Remove(inputFile); err != nil {
    //     return err
    // }


    return nil
}



// Função recursiva para descriptografar uma pasta e seus subdiretórios
func decryptDirectory(key []byte, sourceDir, destDir string) error {
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
			// Descriptografe o arquivo
			if err := decryptFile(key, path, destPath); err != nil {
				return err
			}
		}

		return nil
	})
}

func getDecryptedFileName(encryptedFileName string) string {
	// Remove a extensão ".enc" do nome do arquivo criptografado
	decryptedFileName := strings.TrimSuffix(encryptedFileName, ".enc")
	return decryptedFileName
}

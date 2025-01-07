package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultDir  = ".verify"
	defaultPerm = os.ModePerm
)

func ExitOnError(cmd *cobra.Command, err error) {
	if err == nil {
		return
	}

	_, _ = io.WriteString(cmd.ErrOrStderr(), err.Error()+"\n")
	_ = cmd.Usage()
	os.Exit(1)
}

func WriteString(cmd *cobra.Command, text string) {
	_, _ = io.WriteString(cmd.OutOrStdout(), text+"\n")
}

func WriteAsYAML(cmd *cobra.Command, obj interface{}, writer io.Writer) {
	encoder := yaml.NewEncoder(writer)
	defer encoder.Close()

	encoder.SetIndent(2)
	err := encoder.Encode(obj)
	ExitOnError(cmd, err)
}

func WriteAsJSON(cmd *cobra.Command, obj interface{}, writer io.Writer) {
	b, err := json.MarshalIndent(obj, "", "  ")
	ExitOnError(cmd, err)
	_, _ = writer.Write(b)
}

func WriteAsBinary(cmd *cobra.Command, b []byte, writer io.Writer) {
	_, _ = writer.Write(b)
}

func CreateOrGetDir() (string, error) {
	configDir, err := GetDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(configDir, defaultPerm); err != nil {
		return "", err
	}

	return configDir, nil
}

func GetDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := os.Getenv("VERIFY_HOME")
	if configDir == "" {
		configDir = filepath.Join(homeDir, defaultDir)
	}

	return configDir, nil
}

func UnpackZipToDirectory(cmd *cobra.Command, zipBuffer []byte, outputDirectory string) error {
	if err := os.MkdirAll(outputDirectory, defaultPerm); err != nil {
		return err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipBuffer), int64(len(zipBuffer)))
	if err != nil {
		return err
	}

	// Read all the files from zip archive
	for _, zipFile := range zipReader.File {
		filePath := filepath.Join(outputDirectory, zipFile.Name)
		WriteString(cmd, "Reading file: "+zipFile.Name)
		// if the file is an empty directory, create a directory
		if zipFile.FileInfo().IsDir() {
			// create the directory
			if err := os.MkdirAll(filePath, defaultPerm); err != nil {
				WriteString(cmd, err.Error())
			}
			continue
		}

		// extract the file contents
		unzippedFileBytes, err := readZipFile(zipFile)
		if err != nil {
			WriteString(cmd, err.Error())
			continue
		}

		// create the directory, if it does not exist
		fileDir := filepath.Dir(filePath)
		if err := os.MkdirAll(fileDir, defaultPerm); err != nil {
			WriteString(cmd, err.Error())
		}

		of, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			WriteString(cmd, err.Error())
			continue
		}
		defer of.Close()

		WriteAsBinary(cmd, unzippedFileBytes, of)
	}

	return nil
}

func CreateZipFromDirectory(cmd *cobra.Command, sourceDirectory string) ([]byte, error) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	// Add some files to the archive.
	if err := addFilesToZip(cmd, w, sourceDirectory+"/", ""); err != nil {
		w.Close()
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func addFilesToZip(cmd *cobra.Command, w *zip.Writer, basePath string, baseInZip string) error {
	// Open the Directory
	files, err := os.ReadDir(basePath)
	if err != nil {
		WriteString(cmd, err.Error())
		return err
	}

	for _, file := range files {
		zipFileName := baseInZip + file.Name()
		if !file.IsDir() {
			dat, err := os.ReadFile(basePath + file.Name())
			if err != nil {
				WriteString(cmd, err.Error())
				return err
			}

			// Add file to archive
			f, err := w.Create(zipFileName)
			if err != nil {
				WriteString(cmd, err.Error())
				return err
			}
			_, err = f.Write(dat)
			if err != nil {
				WriteString(cmd, err.Error())
				return err
			}

			WriteString(cmd, "File added: "+zipFileName)
		} else {
			// Recurse
			newBase := basePath + file.Name() + "/"
			WriteString(cmd, "Sub-directory added: "+zipFileName)

			if err := addFilesToZip(cmd, w, newBase, baseInZip+file.Name()+"/"); err != nil {
				return err
			}
		}
	}

	return nil
}

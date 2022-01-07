package logs

import (
	"log"
	"os"
	"os/exec"
)

// WriteLogs structures the logs to be written in a file
type WriteLogs struct {
	Lg   *log.Logger
	File *os.File
}

func dir() string {
	cmd := exec.Command("sudo", "mkdir", "packet-logs")
	err := cmd.Run()
	if err != nil {
		log.Println("exec", err)
	}
	return "./packet-logs/package.log"
}

// WriteIntoLogFile takes an error returning a pointer of type Logger. It locates the home dir,opens the log file and appends log data into the log file
func (l *WriteLogs) WriteIntoLogFile(err error) *log.Logger {
	path := dir()

	l.File, _ = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	l.Lg = log.New(l.File, " packet capture ", log.Ldate|log.Ltime)
	log.SetOutput(l.File)
	l.Lg.Println(err)

	defer l.File.Close()

	return l.Lg
}

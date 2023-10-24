//go:build tools
// +build tools

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/ubuntu/adsys/cmd/adsysd/client"
	"github.com/ubuntu/adsys/cmd/adsysd/daemon"
	"github.com/ubuntu/adsys/cmd/adwatchd/commands"
	"github.com/ubuntu/adsys/internal/generators"
)

const usage = `Usage of %s:

   completion DIRECTORY
     Create completions files in a structured hierarchy in DIRECTORY.
   man DIRECTORY
     Create man pages files in a structured hierarchy in DIRECTORY.
   update-readme
     Update repository README with commands.
   update-doc-cli-ref
	Update repository doc with commands.
`

func main() {
	if len(os.Args) < 2 {
		log.Fatalf(usage, os.Args[0])
	}

	c := client.New()
	d := daemon.New()
	w := commands.New()

	commands := []cobra.Command{c.RootCmd(), d.RootCmd(), w.RootCmd()}
	switch os.Args[1] {
	case "completion":
		if len(os.Args) < 3 {
			log.Fatalf(usage, os.Args[0])
		}
		dir := filepath.Join(generators.DestDirectory(os.Args[2]), "usr", "share")
		genCompletions(commands, dir)
	case "man":
		if len(os.Args) < 3 {
			log.Fatalf(usage, os.Args[0])
		}
		dir := filepath.Join(generators.DestDirectory(os.Args[2]), "usr", "share")
		genManPages(commands, dir)
	case "update-readme":
		if generators.InstallOnlyMode() {
			return
		}
	case "update-doc-cli-ref":
		if generators.InstallOnlyMode() {
			return
		}
		for _, cmd := range commands {
			updateDocReferenceFromCmd(cmd, filepath.Join("docs", "reference", fmt.Sprintf("%s-cli.md", strings.ToLower(cmd.Name()))))
		}
	default:
		log.Fatalf(usage, os.Args[0])
	}
}

// genCompletions for bash and zsh directories
func genCompletions(cmds []cobra.Command, dir string) {
	bashCompDir := filepath.Join(dir, "bash-completion", "completions")
	zshCompDir := filepath.Join(dir, "zsh", "site-functions")
	for _, d := range []string{bashCompDir, zshCompDir} {
		if err := generators.CleanDirectory(filepath.Dir(d)); err != nil {
			log.Fatalln(err)
		}
		if err := generators.CreateDirectory(d, 0755); err != nil {
			log.Fatalf("Couldn't create bash completion directory: %v", err)
		}
	}

	for _, cmd := range cmds {
		if err := cmd.GenBashCompletionFileV2(filepath.Join(bashCompDir, cmd.Name()), true); err != nil {
			log.Fatalf("Couldn't create bash completion for %s: %v", cmd.Name(), err)
		}
		if err := cmd.GenZshCompletionFile(filepath.Join(zshCompDir, cmd.Name())); err != nil {
			log.Fatalf("Couldn't create zsh completion for %s: %v", cmd.Name(), err)
		}
	}
}

func genManPages(cmds []cobra.Command, dir string) {
	manBaseDir := filepath.Join(dir, "man")
	if err := generators.CleanDirectory(manBaseDir); err != nil {
		log.Fatalln(err)
	}

	out := filepath.Join(manBaseDir, "man1")
	if err := generators.CreateDirectory(out, 0755); err != nil {
		log.Fatalf("Couldn't create man pages directory: %v", err)
	}

	for _, cmd := range cmds {
		cmd := cmd
		// Run ExecuteC to install completion and help commands
		_, _ = cmd.ExecuteC()
		opts := doc.GenManTreeOptions{
			Header: &doc.GenManHeader{
				Title: fmt.Sprintf("ADSys: %s", cmd.Name()),
			},
			Path: out,
		}
		if err := genManTreeFromOpts(&cmd, opts); err != nil {
			log.Fatalf("Couldn't generate man pages for %s: %v", cmd.Name(), err)
		}
	}
}

// updateDocReferenceFromCmd creates a file containing the detail of the commands
// the target filePath is relative to the root of the project
func updateDocReferenceFromCmd(cmd cobra.Command, filePath string) {
	_, current, _, ok := runtime.Caller(1)
	if !ok {
		log.Fatal("Couldn't find current file name")
	}

	targetFile := filepath.Join(filepath.Dir(current), "..", filePath)

	tmp, err := os.Create(targetFile + ".new")
	if err != nil {
		log.Fatalf("Couldn't create temporary readme file: %v", err)
	}
	defer tmp.Close()

	mustWriteLine(tmp, fmt.Sprintf("# %s command line\n", cmd.Name()))

	// Write markdown
	user, hidden := getUserAndHiddenCmds(cmd)
	mustWriteLine(tmp, "## User commands\n")
	filterCommandMarkdown(user, tmp)
	mustWriteLine(tmp, "## Hidden commands\n")
	mustWriteLine(tmp, "Those commands are hidden from help and should primarily be used by the system or for debugging.\n")
	filterCommandMarkdown(hidden, tmp)

	if err := tmp.Close(); err != nil {
		log.Fatalf("Couldn't close temporary readme file: %v", err)
	}
	if err := os.Rename(targetFile+".new", targetFile); err != nil {
		log.Fatalf("Couldn't rename to destination readme file: %v", err)
	}
}

func mustWriteLine(w io.Writer, msg string) {
	if _, err := w.Write([]byte(msg + "\n")); err != nil {
		log.Fatalf("Couldn't write %s: %v", msg, err)
	}
}

// genManTreeFromOpts generates a man page for the command and all descendants.
// The pages are written to the opts.Path directory.
// This is a copy from cobra, but it will include Hidden commands.
func genManTreeFromOpts(cmd *cobra.Command, opts doc.GenManTreeOptions) error {
	header := opts.Header
	if header == nil {
		header = &doc.GenManHeader{}
	}
	for _, c := range cmd.Commands() {
		if (!c.IsAvailableCommand() && !c.Hidden) || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := genManTreeFromOpts(c, opts); err != nil {
			return err
		}
	}
	section := "1"
	if header.Section != "" {
		section = header.Section
	}

	separator := "_"
	if opts.CommandSeparator != "" {
		separator = opts.CommandSeparator
	}
	basename := strings.Replace(cmd.CommandPath(), " ", separator, -1)
	filename := filepath.Join(opts.Path, basename+"."+section)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	headerCopy := *header
	return doc.GenMan(cmd, &headerCopy, f)
}

func getUserAndHiddenCmds(cmd cobra.Command) (user []cobra.Command, hidden []cobra.Command) {
	// Run ExecuteC to install completion and help commands
	_, _ = cmd.ExecuteC()
	user = append(user, cmd)
	user = append(user, collectSubCmds(cmd, false /* selectHidden */, false /* parentWasHidden */)...)
	hidden = append(hidden, collectSubCmds(cmd, true /* selectHidden */, false /* parentWasHidden */)...)

	return user, hidden
}

// collectSubCmds get recursiverly commands from a root one.
// It will filter hidden commands if selected, but will present children if needed.
func collectSubCmds(cmd cobra.Command, selectHidden, parentWasHidden bool) (cmds []cobra.Command) {
	for _, c := range cmd.Commands() {
		// Don’t collect command or children (hidden or not) of a hidden command
		if c.Name() == "help" || c.Hidden && !selectHidden {
			continue
		}
		// Add this command if matching request (hidden or non hidden collect).
		// Special case: if a parent is hidden, any children commands (hidden or not) will be selected.
		if (c.Hidden == selectHidden) || (selectHidden && parentWasHidden) {
			cmds = append(cmds, *c)
		}
		// Flip that we have a hidden parent
		currentOrParentHidden := parentWasHidden
		if c.Hidden {
			currentOrParentHidden = true
		}

		cmds = append(cmds, collectSubCmds(*c, selectHidden, currentOrParentHidden)...)
	}
	return cmds
}

// filterCommandMarkdown filters SEE ALSO and add subindentation for commands
// before writing to the writer.
func filterCommandMarkdown(cmds []cobra.Command, w io.Writer) {
	pr, pw := io.Pipe()

	go func() {
		for _, cmd := range cmds {
			if err := doc.GenMarkdown(&cmd, pw); err != nil {
				pw.CloseWithError(fmt.Errorf("couldn't generate markdown for %s: %v", cmd.Name(), err))
				return
			}
		}
		pw.Close()
	}()
	scanner := bufio.NewScanner(pr)
	var skip bool
	for scanner.Scan() {
		l := scanner.Text()
		if strings.HasPrefix(l, "### SEE ALSO") || strings.Contains(l, "Auto generated by") {
			skip = true
		}
		if strings.HasPrefix(l, "## ") {
			skip = false
		}
		if skip {
			continue
		}

		// Add 1 level of subindentation
		if strings.HasPrefix(l, "##") {
			l = "#" + l
		}

		// Special case # Linux an # macOS in shell completion:
		if strings.HasPrefix(l, "# Linux") {
			continue
		} else if strings.HasPrefix(l, "# macOS") {
			l = " or:"
		}

		mustWriteLine(w, l)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Couldn't write generated markdown: %v", err)
	}
}

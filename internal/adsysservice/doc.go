package adsysservice

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/doc"
	"github.com/ubuntu/adsys/internal/authorizer"
	"github.com/ubuntu/adsys/internal/decorate"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
)

// GetDoc returns a chapter documentation from server
// If chapter is empty, all documentation documentation is outputted, with a separator between them.
func (s *Service) GetDoc(r *adsys.GetDocRequest, stream adsys.Service_GetDocServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while getting documentation"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	onlineDocURL := doc.GetPackageURL()

	var out string
	docDir := doc.Dir
	// Get all documentation, separate file names with special characters
	if chapter := r.GetChapter(); chapter == "" {
		fs, err := docDir.ReadDir(".")
		if err != nil {
			return fmt.Errorf(i18n.G("could not list documentation directory: %v"), err)
		}
		// Sort all file names, having a chapter prefix
		var names []string
		for _, f := range fs {
			names = append(names, f.Name())
		}
		sort.Strings(names)

		for _, n := range names {
			d, err := docDir.ReadFile(n)
			if err != nil {
				return err
			}
			out = fmt.Sprintf("%s%s%s\n%s", out, doc.SplitFilesToken, strings.TrimSuffix(n, ".md"), string(d))
		}
	} else {
		// Get a give chapter content
		filename, err := documentChapterToFileName(docDir, chapter)
		if err != nil {
			return err
		}

		f, err := docDir.Open(filename)
		if err != nil {
			return fmt.Errorf(i18n.G("no chapter %q found in documentation"), chapter)
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf(i18n.G("could not read chapter %q: %v"), chapter, err)
		}
		out = fmt.Sprintf("%s%s\n%s", doc.SplitFilesToken, strings.TrimSuffix(filename, ".md"), string(content))
	}
	out = strings.ReplaceAll(out, "(images/", fmt.Sprintf("(%s/images/", onlineDocURL))

	if err := stream.Send(&adsys.StringResponse{
		Msg: out,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send documentation to client: %v", err)
	}
	return nil
}

// ListDoc returns a list of all documentation from server.
func (s *Service) ListDoc(r *adsys.ListDocRequest, stream adsys.Service_ListDocServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while listing documentation"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	fs, err := doc.Dir.ReadDir(".")
	if err != nil {
		return fmt.Errorf(i18n.G("could not list documentation directory: %v"), err)
	}

	// Sort all file names while they have their prefix
	var names []string
	for _, f := range fs {
		names = append(names, f.Name())
	}
	sort.Strings(names)

	var content string
	if !r.GetRaw() {
		content += "# Table of content\n"
	}
	for _, n := range names {
		if r.GetRaw() {
			content += fmt.Sprintln(fileNameToDocumentChapter(n))
			continue
		}
		title := i18n.G("- can't read content -")
		if f, err := doc.Dir.Open(n); err == nil {
			if title, err = bufio.NewReader(f).ReadString('\n'); err == nil {
				title = strings.TrimPrefix(title, "# ")
			}
			if err = f.Close(); err != nil {
				log.Infof(stream.Context(), "Can't close documentation file: %v", err)
			}
		}
		content += fmt.Sprintf("  1. [**%s**] %s\n", fileNameToDocumentChapter(n), title)
	}

	if err := stream.Send(&adsys.StringResponse{
		Msg: content,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send documentation to client: %v", err)
	}
	return nil
}

// fileNameToDocumentChapter strips prefix (before first dash) and suffix of documentation files.
func fileNameToDocumentChapter(name string) string {
	parts := strings.SplitN(name, "-", 2)
	if len(parts) > 1 {
		name = parts[1]
	}
	return strings.TrimSuffix(name, ".md")
}

// documentChapterToFileName returns the first file matching the name of a chapter.
func documentChapterToFileName(dir embed.FS, chapter string) (string, error) {
	fs, err := dir.ReadDir(".")
	if err != nil {
		return "", fmt.Errorf(i18n.G("could not list documentation directory: %v"), err)
	}

	// Sort all file names while they have their prefix
	var names []string
	for _, f := range fs {
		names = append(names, f.Name())
	}
	sort.Strings(names)

	for _, n := range names {
		if strings.EqualFold(fileNameToDocumentChapter(n), chapter) {
			return n, nil
		}
	}

	// Try exact match, posfixing with .md if not found
	if !strings.HasSuffix(chapter, ".md") {
		chapter = fmt.Sprintf("%s.md", chapter)
	}
	if _, err := dir.Open(chapter); err == nil {
		return chapter, nil
	}

	return "", fmt.Errorf(i18n.G("no file found matching chapter %q"), chapter)
}

package adsysservice

import (
	"bufio"
	"embed"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ubuntu/adsys"
	"github.com/ubuntu/adsys/docs"
	"github.com/ubuntu/adsys/internal/authorizer"
	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/decorate"
)

// GetDoc returns a chapter documentation from server.
func (s *Service) GetDoc(r *adsys.GetDocRequest, stream adsys.Service_GetDocServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while getting documentation"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	// Get all documentation metadata
	_, chaptersToFiles, filesToTitle, err := docStructure(docs.Dir, "index.md", "")
	if err != nil {
		return fmt.Errorf(i18n.G("could not list documentation directory: %v"), err)
	}

	// Find a match, removing trailing / for directory folder.
	chapter := strings.TrimSuffix(strings.ToLower(r.GetChapter()), "/")

	p, ok := chaptersToFiles[chapter]
	if !ok {
		return fmt.Errorf("no documentation found for %q", r.GetChapter())
	}

	out, err := renderDocumentationPage(p, filesToTitle)
	if err != nil {
		return fmt.Errorf(i18n.G("could not read chapter %q: %v"), chapter, err)
	}

	if err := stream.Send(&adsys.StringResponse{
		Msg: out,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send documentation to client: %v", err)
	}
	return nil
}

// ListDoc returns a list of all documentation from server.
func (s *Service) ListDoc(_ *adsys.Empty, stream adsys.Service_ListDocServer) (err error) {
	defer decorate.OnError(&err, i18n.G("error while listing documentation"))

	if err := s.authorizer.IsAllowedFromContext(stream.Context(), authorizer.ActionAlwaysAllowed); err != nil {
		return err
	}

	chapters, _, _, err := docStructure(docs.Dir, "index.md", "")
	if err != nil {
		return fmt.Errorf(i18n.G("could not list documentation directory: %v"), err)
	}

	if err := stream.Send(&adsys.ListDocReponse{
		Chapters: chapters,
	}); err != nil {
		log.Warningf(stream.Context(), "couldn't send documentation to client: %v", err)
	}
	return nil
}

// docStructure parses the toc and order documentation based on subsections toc appearance.
// It returns a list of ordered chapters names for completion, a map from chapter name + alias to filename
// and filename to their title name.
// We assume toc trees are only in index files.
func docStructure(dir embed.FS, indexFilePath, parentChapterName string) (orderedChapters []string, chaptersToFiles map[string]string, filesToTitle map[string]string, err error) {
	chaptersToFiles, filesToTitle = make(map[string]string), make(map[string]string)

	f, err := dir.Open(indexFilePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get main index file: %w", err)
	}
	defer f.Close()

	startToctree := "```{toctree}"
	endToctree := "```"

	root := filepath.Dir(indexFilePath)

	var inTocTree bool
	s := bufio.NewScanner(f)
	for s.Scan() {
		t := strings.TrimSpace(s.Text())
		if t == startToctree {
			inTocTree = true
			continue
		} else if t == endToctree {
			inTocTree = false
		}

		// Add the original index
		if strings.HasPrefix(t, "# ") && indexFilePath == "index.md" {
			chaptersToFiles[""] = indexFilePath
			title := strings.TrimPrefix(t, "# ")
			filesToTitle[indexFilePath] = title
			chapterName := toCmdlineChapterName(title, "")
			chaptersToFiles[chapterName] = indexFilePath
			orderedChapters = append(orderedChapters, chapterName)
		}

		if !inTocTree {
			continue
		}

		if strings.HasPrefix(t, ":") || t == "" {
			continue
		}

		// We have 3 forms of content:
		// page -> we need to parse page.md to get its title name
		// foo/index -> we need to parse foo/index.md to get its title name and parse its tocs
		// alias <bar> -> we open bar to get its title name for the reverse lookup, but also adds the alias.
		alias, p, found := strings.Cut(t, "<")
		if found {
			p = strings.TrimSuffix(p, ">")
		} else {
			p = alias
		}
		p = filepath.Join(root, p) + ".md"

		// Automated generated policies, ignore them.
		if p == "reference/policies/index.md" {
			continue
		}

		title, err := titleFromPage(dir, p)
		if err != nil {
			return nil, nil, nil, err
		}
		filesToTitle[p] = title

		chapterName := toCmdlineChapterName(title, parentChapterName)
		chaptersToFiles[chapterName] = p
		// chapterName is either the page title or the alias if set.
		if found {
			alias = toCmdlineChapterName(alias, parentChapterName)
			chaptersToFiles[alias] = p
			chapterName = alias
		}
		orderedChapters = append(orderedChapters, chapterName)

		// Look for any children index files and merge them into the parent one.
		if strings.HasSuffix(p, "index.md") {
			orderedChaptersChild, chaptersToFilesChild, filesToTitleChild, err := docStructure(dir, p, chapterName)
			if err != nil {
				return nil, nil, nil, err
			}

			orderedChapters = append(orderedChapters, orderedChaptersChild...)
			for chapter, p := range chaptersToFilesChild {
				chaptersToFiles[chapter] = p
			}
			for p, title := range filesToTitleChild {
				filesToTitle[p] = title
			}
		}
	}

	if s.Err() != nil {
		return nil, nil, nil, fmt.Errorf("can't scan index file: %w", err)
	}

	return orderedChapters, chaptersToFiles, filesToTitle, err
}

// titleFromPage extracts the title from a given markdown file.
func titleFromPage(dir embed.FS, path string) (string, error) {
	f, err := dir.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	if !s.Scan() {
		return "", fmt.Errorf("empty page")
	}

	title := strings.TrimPrefix(strings.TrimSpace(s.Text()), "# ")

	if s.Err() != nil {
		return "", fmt.Errorf("can't scan file: %w", s.Err())
	}

	return title, nil
}

// toCmdlineChapterName returns lowercase chapter name used for shell completion and user entry.
func toCmdlineChapterName(t, parentChapterName string) string {
	if parentChapterName != "" {
		t = filepath.Join(parentChapterName, t)
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(t), " ", "-"))
}

func renderDocumentationPage(p string, filesToTitle map[string]string) (string, error) {
	var out strings.Builder

	currentDir := filepath.Dir(p)

	f, err := docs.Dir.Open(p)
	if err != nil {
		return "", fmt.Errorf(i18n.G("no file %q found in documentation"), p)
	}
	defer f.Close()

	var inTocTree, shouldRenderTocTree bool
	startToctree := "```{toctree}"
	endToctree := "```"

	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		trimmedLine := strings.TrimSpace(l)
		if trimmedLine == startToctree {
			shouldRenderTocTree = true
			inTocTree = true
			continue
		} else if trimmedLine == endToctree {
			inTocTree = false
			continue
		}

		// Handle to tree content by replacing visible ones with a list of titles or aliases
		if inTocTree {
			if trimmedLine == ":hidden:" {
				shouldRenderTocTree = false
			}
			if strings.HasPrefix(trimmedLine, ":") || !shouldRenderTocTree || trimmedLine == "" {
				continue
			}

			title, _, aliasFound := strings.Cut(trimmedLine, "<")
			if !aliasFound {
				p = filepath.Join(currentDir, title) + ".md"
				title = filesToTitle[p]
			}

			l = fmt.Sprintf(" * %s", title)
		}

		// Strip grids
		if strings.HasPrefix(l, "````") || strings.HasPrefix(l, "```{grid") {
			continue
		}
		/*
			### [Explanation](explanation/index) -> ### Explanation
		*/
		// Replace image urls
		if strings.HasPrefix(l, "![") {
			l = imageURLToRTDURL(l)
		}

		// Remove all remaining internal links for now as we can't bind them.
		l = stripInternalLinks(l)

		_, err := out.Write([]byte(l + "\n"))
		if err != nil {
			return "", err
		}
	}

	if s.Err() != nil {
		return "", fmt.Errorf("can't scan file: %w", s.Err())
	}

	return out.String(), nil
}

var reURL = regexp.MustCompile(`\.\./images/(.+/)*`)

// imageURLToRTDURL rewrites images links to match Read the Docs format.
func imageURLToRTDURL(imageLine string) string {
	return reURL.ReplaceAllString(imageLine, docs.RTDRootURL+"/_images/")
}

// Regular expression pattern to match [title](URL).
var reInternalLinksURL = regexp.MustCompile(`\[(.*?)\]\(.*?\)`)

// stripInternalLinks strips the link part from URL.
func stripInternalLinks(line string) string {
	if strings.Contains(line, "http") {
		return line
	}

	return reInternalLinksURL.ReplaceAllString(line, "$1")
}

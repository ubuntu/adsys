package watchdtui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ubuntu/adsys/internal/i18n"
	"github.com/ubuntu/adsys/internal/watchdhelpers"
	"github.com/ubuntu/adsys/internal/watchdservice"
	"golang.org/x/exp/slices"
)

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#99cc99"))
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	hintStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	cursorStyle  = focusedStyle.Copy()
	noStyle      = lipgloss.NewStyle()
	boldStyle    = lipgloss.NewStyle().Bold(true)
	titleStyle   = lipgloss.NewStyle().Underline(true).Bold(true)
	focusedStyle = boldStyle.Copy().Foreground(lipgloss.Color("#E95420")) // Ubuntu orange

	submitText    = i18n.G("Install")
	focusedButton = focusedStyle.Copy().Render(fmt.Sprintf("[ %s ]", submitText))
	blurredButton = fmt.Sprintf("[ %s ]", blurredStyle.Render(submitText))
)

type model struct {
	focusIndex    int
	inputs        []textinput.Model
	spinner       spinner.Model
	defaultConfig string

	err       error
	loading   bool
	typing    bool
	installed bool

	dryrun bool
}

type appConfig struct {
	Verbose int
	Dirs    []string
}

type installMsg struct {
	err error
}

// installService writes the configuration file and installs the service with
// the file as an argument.
func (m model) installService(confFile string, dirsMap map[string]struct{}) tea.Cmd {
	return func() tea.Msg {
		// If the user typed in a directory, create the config file inside it
		if stat, err := os.Stat(confFile); confFile == "" || err == nil && stat.IsDir() {
			confFile = filepath.Join(confFile, "adwatchd.yml")
		}

		// Convert directories to a string slice
		var dirs []string
		for dir := range dirsMap {
			dirs = append(dirs, dir)
		}

		// Sort the directories to avoid nondeterministic behavior
		slices.Sort(dirs)

		if err := watchdhelpers.WriteConfig(confFile, dirs, m.defaultConfig); err != nil {
			return installMsg{err}
		}

		configAbsPath, err := filepath.Abs(confFile)
		if err != nil {
			return installMsg{err}
		}

		svc, err := watchdservice.New(
			context.Background(),
			watchdservice.WithArgs([]string{"-c", configAbsPath}),
		)
		if err != nil {
			return installMsg{err}
		}

		// Only install service on a real system
		if m.dryrun {
			return installMsg{nil}
		}

		err = svc.Install(context.Background())
		return installMsg{err}
	}
}

// initialModel builds and returns the initial model.
func initialModel(configFile string, isDefault bool) model {
	dirCount := 1
	s := spinner.New()
	s.Spinner = spinner.Dot

	// Attempt to read directories from the config file
	previousDirs := watchdhelpers.GetDirsFromConfigFile(configFile)
	previousDirs = watchdhelpers.FilterAbsentDirs(previousDirs)
	if len(previousDirs) > 0 {
		dirCount = len(previousDirs)
	}

	m := model{
		// Start with a size of at least 2 (one for the config path, one for the first
		// configured directory, the slice will be resized based on user input).
		inputs:        make([]textinput.Model, dirCount+1),
		spinner:       s,
		typing:        true,
		defaultConfig: configFile,
	}

	var t textinput.Model
	for i := range m.inputs {
		t = newStyledTextInput()

		switch i {
		case 0:
			t.Placeholder = fmt.Sprintf(i18n.G("Config file location (leave blank for default: %s)"), m.defaultConfig)
			t.Prompt = i18n.G("Config file: ")
			t.PromptStyle = boldStyle
			t.Focus()

			// Only prefill the config path if we received it via argument, even
			// if it's the default one.
			if !isDefault {
				t.SetValue(m.defaultConfig)
			}
		case 1:
			t.Placeholder = i18n.G("Directory to watch (one per line)")
		}

		m.inputs[i] = t
	}

	// If we managed to read directories from the "previous" config file,
	// prefill them
	for index, dir := range previousDirs {
		m.inputs[index+1].SetValue(dir)
	}

	return m
}

// newStyledTextInput returns a new text input with the default style.
func newStyledTextInput() textinput.Model {
	t := textinput.New()
	t.CursorStyle = cursorStyle
	t.CharLimit = 1024
	t.SetCursorMode(textinput.CursorStatic)
	return t
}

// Init returns the initial command for the application to run.
func (m model) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles incoming events and updates the model accordingly.
func (m model) Update(teaMsg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := teaMsg.(type) {
	case installMsg:
		m.loading = false
		m.installed = true
		if err := msg.err; err != nil {
			m.err = err
		}

		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyUp, tea.KeyShiftTab:
			// Block if the directory input is invalid
			if m.focusIndex > 0 && m.focusIndex < len(m.inputs) && m.inputs[m.focusIndex].Err != nil {
				break
			}

			// Set focus to previous input
			m.focusIndex--
			if m.focusIndex < 0 {
				m.focusIndex = 0
			}

		case tea.KeyDown, tea.KeyTab:
			// Block if the directory input is invalid
			if m.focusIndex > 0 && m.focusIndex < len(m.inputs) && m.inputs[m.focusIndex].Err != nil {
				break
			}

			// Set focus to next input
			m.focusIndex++
			if m.focusIndex > len(m.inputs) {
				m.focusIndex = len(m.inputs)
			}

		case tea.KeyBackspace:
			// backspace: set focus to previous input if needed

			// No backspace on config
			if m.focusIndex == 0 {
				break
			}

			// Backspace on submit: go to previous one
			if m.focusIndex == len(m.inputs) {
				m.focusIndex--
				// tell that we already handled backspace by changing the message type to nothing
				// This prevents input to handle again backspace.
				teaMsg = struct{}{}
				break
			}

			// If element is not empty, let the input widget handling it
			if m.inputs[m.focusIndex].Value() != "" {
				break
			}

			// Handle element removal on any empty directory input
			if m.focusIndex > 1 {
				m.inputs = slices.Delete(m.inputs, m.focusIndex, m.focusIndex+1)
				m.focusIndex--
				// tell that we already handled backspace by changing the message type to nothing
				// This prevents input to handle again backspace.
				teaMsg = struct{}{}
				break
			}
			m.focusIndex--

		case tea.KeyEnter:
			// Did the user press enter while the submit button was focused?
			if m.focusIndex == len(m.inputs) {
				var confFile string
				var dirs = make(map[string]struct{})

				// Normalize the directory inputs, skip duplicates and empty
				// ones
				for _, i := range m.inputs[1:] {
					if i.Value() != "" {
						absDir, err := filepath.Abs(i.Value())
						if err != nil {
							m.err = err
							return m, nil
						}

						dirs[filepath.Clean(absDir)] = struct{}{}
					}
				}

				confFile = m.inputs[0].Value()

				m.typing = false
				m.loading = true

				//return m, m.installService(confFile, dirs)
				return m, tea.Batch(m.spinner.Tick, m.installService(confFile, dirs))
			}

			// Always go to directory from config
			if m.focusIndex == 0 {
				m.focusIndex++
				break
			}

			// Directory fields
			switch m.inputs[m.focusIndex].Value() {
			case "":
				// We need at least one directory to watch. Block action.
				if m.focusIndex == 1 {
					break
				}

				// delete the current (empty) one, focus stays the same index to move to next element
				m.inputs = slices.Delete(m.inputs, m.focusIndex, m.focusIndex+1)

			default:
				if m.inputs[m.focusIndex].Err != nil {
					break
				}
				// add a new input where we are and move focus to it
				m.focusIndex++
				m.inputs = slices.Insert(m.inputs, m.focusIndex, newStyledTextInput())
			}
		}
	}

	// General properties
	if m.installed {
		time.Sleep(time.Second * 2)

		return m, tea.Quit
	}

	if m.loading {
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(teaMsg)
		return m, cmd
	}

	if m.typing {
		// Handle character input and blinking
		cmd := m.updateInputs(teaMsg)
		return m, cmd
	}

	return m, nil
}

// updateInputs handles the input of the user.
func (m *model) updateInputs(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd

	for i := range m.inputs {
		// Style the input depending on focus
		if i != m.focusIndex {
			// Ensure focused state is removed
			m.inputs[i].Blur()
			m.inputs[i].PromptStyle = boldStyle
			m.inputs[i].TextStyle = noStyle
			continue
		}

		// Set focused state
		m.inputs[i].PromptStyle = focusedStyle

		// Record change of focus if current element was not already focused
		if !m.inputs[i].Focused() {
			cmds = append(cmds, m.inputs[i].Focus())
		}

		// Only text inputs with Focus() set will respond, so it's safe to simply
		// update all of them here without any further logic
		var update tea.Cmd
		m.inputs[i], update = m.inputs[i].Update(msg)

		// Update input style/error separately for config and directories
		if m.focusIndex > 0 {
			m.updateDirInputErrorAndStyle(i)
		} else {
			updateConfigInputError(&m.inputs[0])
		}
		cmds = append(cmds, update)
	}

	return tea.Batch(cmds...)
}

// updateConfigInputError updates the error state of the config input.
func updateConfigInputError(input *textinput.Model) {
	value := input.Value()
	// If the config input is empty, clean up the error message
	if value == "" {
		input.Err = nil
		return
	}

	absPath, _ := filepath.Abs(value)
	stat, err := os.Stat(value)

	// If the config file does not exist, we're good
	if errors.Is(err, os.ErrNotExist) {
		if filepath.IsAbs(value) {
			input.Err = nil
		} else {
			input.Err = fmt.Errorf(i18n.G("%s will be the absolute path"), absPath)
		}
		return
	}

	// If we got another error, display it
	if err != nil {
		input.Err = err
		return
	}

	if stat.IsDir() {
		input.Err = fmt.Errorf(i18n.G("%s is a directory; will create adwatchd.yml inside"), absPath)
		return
	}

	if stat.Mode().IsRegular() {
		input.Err = fmt.Errorf(i18n.G("%s: file already exists and will be overwritten"), absPath)
		return
	}

	input.Err = nil
}

// updateDirInputErrorAndStyle updates the error message and style of the given directory input.
func (m *model) updateDirInputErrorAndStyle(i int) {
	// We consider an empty string to be valid, so users are allowed to press
	// enter on it.
	if m.inputs[i].Value() == "" {
		if len(m.inputs) == 2 {
			m.inputs[i].Err = errors.New(i18n.G("please enter at least one directory"))
		} else {
			m.inputs[i].Err = nil
		}
		return
	}

	// Check to see if the input exists, and if it is a directory
	absPath, _ := filepath.Abs(m.inputs[i].Value())
	if stat, err := os.Stat(absPath); err != nil {
		m.inputs[i].Err = fmt.Errorf(i18n.G("%s: directory does not exist, please enter a valid path"), absPath)
		m.inputs[i].TextStyle = noStyle
	} else if !stat.IsDir() {
		m.inputs[i].Err = fmt.Errorf(i18n.G("%s: is not a directory"), absPath)
		m.inputs[i].TextStyle = noStyle
	} else {
		m.inputs[i].Err = nil
		m.inputs[i].TextStyle = successStyle
	}

}

// View renders the UI based on the data in the model.
func (m model) View() string {
	if m.loading {
		return fmt.Sprintf(i18n.G("%s installing service... please wait."), m.spinner.View())
	}

	if err := m.err; err != nil {
		return fmt.Sprintf(i18n.G("Could not install service: %v\n"), err)
	}

	if m.typing {
		var b strings.Builder

		b.WriteString(titleStyle.Render(i18n.G("Ubuntu AD Watch Daemon Installer")))
		b.WriteString("\n\n")

		// Display config input and hint
		b.WriteString(m.inputs[0].View())
		if m.inputs[0].Err != nil {
			b.WriteRune('\n')
			b.WriteString(hintStyle.Render(m.inputs[0].Err.Error()))
			b.WriteString("\n\n")
		} else {
			b.WriteString("\n\n\n")
		}

		directoriesMsg := i18n.G("Directories:")
		if m.focusIndex > 0 && m.focusIndex < len(m.inputs) {
			b.WriteString(focusedStyle.Render(directoriesMsg))
		} else {
			b.WriteString(boldStyle.Render(directoriesMsg))
		}
		b.WriteRune('\n')

		// Display directory inputs
		for i, v := range m.inputs[1:] {
			_, _ = b.WriteString(v.View())
			if i < len(m.inputs)-1 {
				_, _ = b.WriteRune('\n')
			}
		}

		// Display directory error if any
		if m.focusIndex > 0 && m.focusIndex < len(m.inputs) && m.inputs[m.focusIndex].Err != nil {
			b.WriteString(hintStyle.Render(m.inputs[m.focusIndex].Err.Error()))
		}

		// Display button
		button := &blurredButton
		if m.focusIndex == len(m.inputs) {
			button = &focusedButton
		}
		_, _ = fmt.Fprintf(&b, "\n\n%s\n", *button)

		return b.String()
	}

	return fmt.Sprintln(i18n.G("Service adwatchd was successfully installed and is now running."))
}

// Start starts the interactive TUI.
func Start(ctx context.Context, configFile string, isDefault bool) error {
	p := tea.NewProgram(initialModel(configFile, isDefault))
	if err := p.Start(); err != nil {
		return err
	}
	return nil
}

package watchdtui

// InitialModelForTests returns an instance of the initial model that will not
// install the service.
func InitialModelForTests(configFile string, isDefaultConfig bool) Model {
	m := initialModel(configFile, isDefaultConfig)
	m.dryrun = true
	return m
}

// InitialModel returns an instance of the initial model with default values,
// suitable for integration tests.
func InitialModel() Model {
	m := initialModel("adwatchd.yaml", true)
	return m
}

type Model = model

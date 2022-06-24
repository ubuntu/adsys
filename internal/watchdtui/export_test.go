package watchdtui

// InitialModelForTests returns an instance of the initial model that will not
// install the service.
func InitialModelForTests(configFile string, prevConfig string, isDefaultConfig bool) Model {
	m := initialModel(configFile, prevConfig, isDefaultConfig)
	m.dryrun = true
	return m
}

// InitialModel returns an instance of the initial model with default values,
// suitable for integration tests.
func InitialModel() Model {
	return initialModel("adwatchd.yaml", "", true)
}

// InitialModel returns an instance of the initial model with default values,
// and a previous config file suitable for integration tests.
func InitialModelWithPrevConfig(configFile string, prevConfig string, defaultConfig bool) Model {
	return initialModel(configFile, prevConfig, defaultConfig)
}

type Model = model

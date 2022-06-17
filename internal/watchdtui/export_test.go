package watchdtui

// InitialModelForTests returns an instance of the initial model that will not
// install the service.
func InitialModelForTests(configFile string, isDefaultConfig bool) model {
	m := initialModel(configFile, isDefaultConfig)
	m.dryrun = true
	return m
}

// InitialModel returns an instance of the initial model with default values,
// suitable for integration tests.
func InitialModel() model {
	m := initialModel("adwatchd.yml", true)
	return m
}

type Model = model
type AppConfig = appConfig

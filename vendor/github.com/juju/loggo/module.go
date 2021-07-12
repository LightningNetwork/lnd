// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package loggo

// Do not change rootName: modules.resolve() will misbehave if it isn't "".
const (
	rootString       = "<root>"
	defaultRootLevel = WARNING
	defaultLevel     = UNSPECIFIED
)

type module struct {
	name    string
	level   Level
	parent  *module
	context *Context
}

// Name returns the module's name.
func (module *module) Name() string {
	if module.name == "" {
		return rootString
	}
	return module.name
}

func (m *module) willWrite(level Level) bool {
	if level < TRACE || level > CRITICAL {
		return false
	}
	return level >= m.getEffectiveLogLevel()
}

func (module *module) getEffectiveLogLevel() Level {
	// Note: the root module is guaranteed to have a
	// specified logging level, so acts as a suitable sentinel
	// for this loop.
	for {
		if level := module.level.get(); level != UNSPECIFIED {
			return level
		}
		module = module.parent
	}
	panic("unreachable")
}

// setLevel sets the severity level of the given module.
// The root module cannot be set to UNSPECIFIED level.
func (module *module) setLevel(level Level) {
	// The root module can't be unspecified.
	if module.name == "" && level == UNSPECIFIED {
		level = WARNING
	}
	module.level.set(level)
}

func (m *module) write(entry Entry) {
	entry.Module = m.name
	m.context.write(entry)
}

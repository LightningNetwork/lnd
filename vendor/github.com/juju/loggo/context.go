// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package loggo

import (
	"fmt"
	"strings"
	"sync"
)

// Context produces loggers for a hierarchy of modules. The context holds
// a collection of hierarchical loggers and their writers.
type Context struct {
	root *module

	// Perhaps have one mutex?
	modulesMutex sync.Mutex
	modules      map[string]*module

	writersMutex sync.Mutex
	writers      map[string]Writer

	// writeMuxtex is used to serialise write operations.
	writeMutex sync.Mutex
}

// NewLoggers returns a new Context with no writers set.
// If the root level is UNSPECIFIED, WARNING is used.
func NewContext(rootLevel Level) *Context {
	if rootLevel < TRACE || rootLevel > CRITICAL {
		rootLevel = WARNING
	}
	context := &Context{
		modules: make(map[string]*module),
		writers: make(map[string]Writer),
	}
	context.root = &module{
		level:   rootLevel,
		context: context,
	}
	context.root.parent = context.root
	context.modules[""] = context.root
	return context
}

// GetLogger returns a Logger for the given module name, creating it and
// its parents if necessary.
func (c *Context) GetLogger(name string) Logger {
	name = strings.TrimSpace(strings.ToLower(name))
	c.modulesMutex.Lock()
	defer c.modulesMutex.Unlock()
	return Logger{c.getLoggerModule(name)}
}

func (c *Context) getLoggerModule(name string) *module {
	if name == rootString {
		name = ""
	}
	impl, found := c.modules[name]
	if found {
		return impl
	}
	parentName := ""
	if i := strings.LastIndex(name, "."); i >= 0 {
		parentName = name[0:i]
	}
	parent := c.getLoggerModule(parentName)
	impl = &module{name, UNSPECIFIED, parent, c}
	c.modules[name] = impl
	return impl
}

// Config returns the current configuration of the Loggers. Loggers
// with UNSPECIFIED level will not be included.
func (c *Context) Config() Config {
	result := make(Config)
	c.modulesMutex.Lock()
	defer c.modulesMutex.Unlock()

	for name, module := range c.modules {
		if module.level != UNSPECIFIED {
			result[name] = module.level
		}
	}
	return result
}

// CompleteConfig returns all the loggers and their defined levels,
// even if that level is UNSPECIFIED.
func (c *Context) CompleteConfig() Config {
	result := make(Config)
	c.modulesMutex.Lock()
	defer c.modulesMutex.Unlock()

	for name, module := range c.modules {
		result[name] = module.level
	}
	return result
}

// ApplyConfig configures the logging modules according to the provided config.
func (c *Context) ApplyConfig(config Config) {
	c.modulesMutex.Lock()
	defer c.modulesMutex.Unlock()
	for name, level := range config {
		module := c.getLoggerModule(name)
		module.setLevel(level)
	}
}

// ResetLoggerLevels iterates through the known logging modules and sets the
// levels of all to UNSPECIFIED, except for <root> which is set to WARNING.
func (c *Context) ResetLoggerLevels() {
	c.modulesMutex.Lock()
	defer c.modulesMutex.Unlock()
	// Setting the root module to UNSPECIFIED will set it to WARNING.
	for _, module := range c.modules {
		module.setLevel(UNSPECIFIED)
	}
}

func (c *Context) write(entry Entry) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	for _, writer := range c.getWriters() {
		writer.Write(entry)
	}
}

func (c *Context) getWriters() []Writer {
	c.writersMutex.Lock()
	defer c.writersMutex.Unlock()
	var result []Writer
	for _, writer := range c.writers {
		result = append(result, writer)
	}
	return result
}

// AddWriter adds a writer to the list to be called for each logging call.
// The name cannot be empty, and the writer cannot be nil. If an existing
// writer exists with the specified name, an error is returned.
func (c *Context) AddWriter(name string, writer Writer) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if writer == nil {
		return fmt.Errorf("writer cannot be nil")
	}
	c.writersMutex.Lock()
	defer c.writersMutex.Unlock()
	if _, found := c.writers[name]; found {
		return fmt.Errorf("context already has a writer named %q", name)
	}
	c.writers[name] = writer
	return nil
}

// Writer returns the named writer if one exists.
// If there is not a writer with the specified name, nil is returned.
func (c *Context) Writer(name string) Writer {
	c.writersMutex.Lock()
	defer c.writersMutex.Unlock()
	return c.writers[name]
}

// RemoveWriter remotes the specified writer. If a writer is not found with
// the specified name an error is returned. The writer that was removed is also
// returned.
func (c *Context) RemoveWriter(name string) (Writer, error) {
	c.writersMutex.Lock()
	defer c.writersMutex.Unlock()
	reg, found := c.writers[name]
	if !found {
		return nil, fmt.Errorf("context has no writer named %q", name)
	}
	delete(c.writers, name)
	return reg, nil
}

// ReplaceWriter is a convenience method that does the equivalent of RemoveWriter
// followed by AddWriter with the same name. The replaced writer is returned.
func (c *Context) ReplaceWriter(name string, writer Writer) (Writer, error) {
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}
	if writer == nil {
		return nil, fmt.Errorf("writer cannot be nil")
	}
	c.writersMutex.Lock()
	defer c.writersMutex.Unlock()
	reg, found := c.writers[name]
	if !found {
		return nil, fmt.Errorf("context has no writer named %q", name)
	}
	oldWriter := reg
	c.writers[name] = writer
	return oldWriter, nil
}

// ResetWriters is generally only used in testing and removes all the writers.
func (c *Context) ResetWriters() {
	c.writersMutex.Lock()
	defer c.writersMutex.Unlock()
	c.writers = make(map[string]Writer)
}

// ConfigureLoggers configures loggers according to the given string
// specification, which specifies a set of modules and their associated
// logging levels.  Loggers are colon- or semicolon-separated; each
// module is specified as <modulename>=<level>.  White space outside of
// module names and levels is ignored.  The root module is specified
// with the name "<root>".
//
// An example specification:
//	`<root>=ERROR; foo.bar=WARNING`
func (c *Context) ConfigureLoggers(specification string) error {
	config, err := ParseConfigString(specification)
	if err != nil {
		return err
	}
	c.ApplyConfig(config)
	return nil
}

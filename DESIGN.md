# Project architecture

The main component of this tool is the Ghidra plugin, `AngrIntegrationPlugin` (in `plugin/AngrIntegration`). This creates a
Ghidra UI Component (in `AngrIntegrationProvider`), and creates an `AngrInterface` which is responsible for communicating
with angr. It also aquires the `ConsoleService` for printing to the console and wraps it in it's own methods for
outputting data.

## `AngrInterface`

Responsible for running scripts for the plugin. Stores the paths to python and keeps track of currently running worker
threads.

When the `AngrIntegrationProvider` tells the interface to run angr, a `Process` is created, which corresponds to an
actually running instance of Python (in the venv). This is passed to a Swing `SwingWorker`, which polls the
stdin/out/err every 20ms for new output. If there is new output, it will send it to either the REPL or the console,
depending on if the REPL is active or not.

The `AngrInterface` is also responsible for interpreteting several special commands the python process can send, which are
all prefixed by a string that's unlikely to be hit normally (currently "`!<*`"). These can do things like send status
updates to the UI, or cause the `AngrInterface` to create the REPL window and start sending data to that instead.

If the REPL is active, it will call `checkSendInput` on the `AngrREPL` object every 20ms, which forwards updates from
the user down the pipes to the angr process.

## `AngrIntegrationProvider`

High level component for the UI. Constructs each tab of the UI, registers event handlers, and does any other UI setup
that needs doing. The tables, components that are shown or hidden by buttons, and Hook panels are delegated to other
classes due to their complexity.

Shows status reports from the `AngrInterface` next to the run button. Receives events from the `AngrIntegrationPlugin`
when the program is changed, to allow the various components to adjust.

When the run button is clicked, the `Provider` gathers all the fields from the UI into a `AngrConfiguration` object,
which is serialized and written to a file in `/tmp`. Then the `AngrInterface` invokes the `angr_main` script, which
reads that file and uses it to run angr!

## `GoalView` and `StateView`

These subclass Ghidra's `OptionalComponent` which is an abstract class that defines a component that can be shown, and also respond to events when the program is changed or readied. These are used to define the components in the UI when the corresponding button is selected for exploration goal or entry point respectively. When it's time to construct the `AngrConfiguration`, the `getConfig` function is called on them which should return the `ExplorationGoal` or `EntryPoint` that should be written to the `AngrConfiguration`.

Each `_GoalView` corresponds to a `_Goal` that represents that goal in an `AngrConfiguration`, and respectively for `_StateView`.

## `Table` and `TableModel`

These are just specialisations of `JTable`s and `TableModel`s that configure the table to fit our needs.

## `HookView`

This component draws the edit panel for an individual hook. Unlike most of the UI, changes made in the UI are
immediately written to an underlying array of `Hook`s, which means that only one `HookView` needs to exist.

## `AngrREPL`

Wraps a `InterpreterComponentProvider` in a small interface for reading and writing to it.

## Python

### `get_angr_version`

Invoked by the plugin when loading or the venv changes, to check that the correct version of angr is loaded.

### `angr_main`

The main entry point to angr in the plugin. This reads a passed in data file, which should be a JSON object created from
the `AngrInterface`, which defines everything that's been written into the UI.

This does some setup, which includes using the `symbolic_field` module to construct symbolic variables and constraints
from provided python strings, and inserting the progress reporter `ExplorationTechinique` from `progress_reporter`,
which periodically writes progress reports which are picked up by the `AngrInterface` connected to stdout. It will also
load the architecture definition from the provided config, which contains many hooks that can trigger across the whole
process.

Then it runs the main angr process, which should probably take a while! When done, it will print some cursory
information about the recovered states and, if configured to do so, signal the interface to move to a REPL before
starting a repl interpreter itself.

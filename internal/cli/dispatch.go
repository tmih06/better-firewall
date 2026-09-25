package cli

// dispatch routes the command word. Implemented across commands_*.go.
func (e *Env) dispatch(args []string) int {
	switch args[0] {
	case "enable":
		return e.cmdEnable(args[1:])
	case "disable":
		return e.cmdDisable(args[1:])
	case "reload":
		return e.cmdReload(args[1:])
	case "reset":
		return e.cmdReset(args[1:])
	case "default":
		return e.cmdDefault(args[1:])
	case "logging":
		return e.cmdLogging(args[1:])
	case "status":
		return e.cmdStatus(args[1:])
	case "show":
		return e.cmdShow(args[1:])
	case "app":
		return e.cmdApp(args[1:])
	case "set":
		return e.cmdSet(args[1:])
	case "nat":
		return e.cmdNat(args[1:])
	case "check":
		return e.cmdCheck(args[1:])
	case "diff":
		return e.cmdDiff(args[1:])
	case "panic":
		return e.cmdPanic(args[1:])
	case "export":
		return e.cmdExport(args[1:])
	case "import":
		return e.cmdImport(args[1:])
	case "import-ufw":
		return e.cmdImportUFW(args[1:])
	case "migrate":
		return e.cmdMigrate(args[1:])
	case "sweep":
		return e.cmdSweep(args[1:])
	case "protect":
		return e.cmdProtect(args[1:])
	case "logs":
		return e.cmdLogs(args[1:])
	case "version":
		// `bfw version` — ufw parity; same output as --version.
		e.Msg("%s %s", e.Prog, e.Version)
		return 0
	case "rule":
		// 'rule enable|disable NUM' is the bfw toggle extension; any other
		// 'rule …' is the ufw optional keyword → fall through to rule ops.
		if len(args) > 1 && (args[1] == "enable" || args[1] == "disable") {
			return e.cmdRule(args[1:])
		}
		return e.cmdRuleOp(args)
	case "boot-load":
		return e.cmdBootLoad(args[1:])
	case "boot-unload":
		return e.cmdBootUnload(args[1:])
	case "allow", "deny", "reject", "limit", "delete", "insert", "prepend", "route":
		return e.cmdRuleOp(args)
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
}

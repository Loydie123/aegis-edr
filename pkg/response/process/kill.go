package process

type ProcessTreeKiller interface {
	KillTree(pid int) error
}

func NewProcessTreeKiller() ProcessTreeKiller {
	return newProcessTreeKiller()
}

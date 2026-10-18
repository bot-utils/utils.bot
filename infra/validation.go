package main

func serverImageTarget(check, account string, local, edge, public bool) string {
	if check == "" || check == "0" {
		return "runtime"
	}
	if check != "1" || local || !edge || public {
		panic("independent check requires the private production account/edge")
	}
	requireDeploymentAccount(account, false)
	return "private-edge-check"
}

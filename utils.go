package main

// confCorsListToString converts a list of strings to a comma separated string
func confCorsListToString(list []string) string {
	var corsList string
	for i, cors := range list {
		if i == 0 {
			corsList = cors
		} else {
			corsList = corsList + "," + cors
		}
	}
	return corsList
}
